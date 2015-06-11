package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/shipyard/shpd/manager"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const (
	appSessionName = "shpd"
	githubBaseURL  = "https://api.github.com"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
)

type Api struct {
	listenAddr        string
	manager           *manager.Manager
	store             sessions.Store
	oauthClientID     string
	oauthClientSecret string
	oauthScopes       []string
	allowedUsers      []string
}

type GithubUser struct {
	Login string `json:"login,omitempty"`
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

type Credentials struct {
	Username string `json:"username,omitempty"`
	Token    string `json:"token,omitempty"`
}

type ApiConfig struct {
	Listen            string
	RedisAddr         string
	RedisPassword     string
	SessionSecret     string
	AwsID             string
	AwsKey            string
	R53ZoneID         string
	DefaultTTL        int64
	ReservedPrefixes  []string
	MaxUserDomains    int
	OAuthClientID     string
	OAuthClientSecret string
	AllowedUsers      []string
}

func getGithubURL(path string) string {
	return fmt.Sprintf("%s%s", githubBaseURL, path)
}

func NewApi(config *ApiConfig) (*Api, error) {
	mgr, err := manager.NewManager(config.RedisAddr, config.RedisPassword, config.AwsID, config.AwsKey, config.R53ZoneID, config.DefaultTTL, config.ReservedPrefixes, config.MaxUserDomains)
	if err != nil {
		return nil, err
	}

	oauthScopes := []string{"user:email"}

	store := sessions.NewCookieStore([]byte(config.SessionSecret))

	return &Api{
		listenAddr:        config.Listen,
		manager:           mgr,
		store:             store,
		oauthClientID:     config.OAuthClientID,
		oauthClientSecret: config.OAuthClientSecret,
		oauthScopes:       oauthScopes,
		allowedUsers:      config.AllowedUsers,
	}, nil
}

func (a *Api) getOAuthConfig() *oauth2.Config {
	conf := &oauth2.Config{
		ClientID:     a.oauthClientID,
		ClientSecret: a.oauthClientSecret,
		Scopes:       a.oauthScopes,
		Endpoint:     github.Endpoint,
	}

	return conf
}

func (a *Api) getSession(r *http.Request) (*sessions.Session, error) {
	return a.store.Get(r, "shpd")
}

func (a *Api) isValidUser(username string) bool {
	if len(a.allowedUsers) == 0 {
		return true
	}

	for _, u := range a.allowedUsers {
		if u == username {
			return true
		}
	}

	return false
}

func (a *Api) getUsernameAndToken(r *http.Request) (string, string, error) {
	username := ""
	token := ""

	session, _ := a.getSession(r)
	u := session.Values["username"]
	t := session.Values["token"]

	if u != nil {
		username = u.(string)
	}

	if t != nil {
		token = t.(string)
	}

	if username == "" || token == "" {
		return "", "", ErrUnauthorized
	}

	return username, token, nil
}

func (a *Api) authRequiredMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := ""
		token := ""

		session, _ := a.getSession(r)
		u := session.Values["username"]
		t := session.Values["token"]

		if u != nil {
			username = u.(string)
		}

		if t != nil {
			token = t.(string)
		}

		if err := a.manager.ValidateToken(username, token); err == nil {
			next.ServeHTTP(w, r)
			return
		}

		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func (a *Api) login(w http.ResponseWriter, r *http.Request) {
	// redirect to oauth url
	conf := a.getOAuthConfig()

	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

func (a *Api) getOAuthClient(code string) (*http.Client, error) {
	conf := a.getOAuthConfig()

	token, err := conf.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, err
	}

	return conf.Client(oauth2.NoContext, token), nil
}

func (a *Api) authCallback(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")

	client, err := a.getOAuthClient(code)

	u := getGithubURL("/user")
	resp, err := client.Get(u)
	if err != nil {
		log.Errorf("error getting user info: %s", err)
		return
	}

	var userInfo *GithubUser

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		log.Errorf("error parsing github user info: %s", err)
		return
	}

	shpdToken, err := a.manager.GenerateToken(userInfo.Login)
	if err != nil {
		log.Errorf("error generating token: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// write to session
	session, _ := a.getSession(r)
	session.Values["username"] = shpdToken.Username
	session.Values["token"] = shpdToken.Token
	session.Values["code"] = code
	sessions.Save(r, w)

	log.Debugf("authenticated user: username=%s", shpdToken.Username)

	// check allowed user
	if !a.isValidUser(shpdToken.Username) {
		log.Warnf("unauthorized login: username=%s ip=%s", shpdToken.Username, r.RemoteAddr)
		//http.Error(w, "forbidden", http.StatusForbidden)
		http.Redirect(w, r, "/#/403", http.StatusFound)
		return
	}

	// redirect to domains
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *Api) logout(w http.ResponseWriter, r *http.Request) {
	username, token, err := a.getUsernameAndToken(r)
	if err != nil {
		log.Errorf("error getting user token: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := a.manager.DeleteToken(username, token); err != nil {
		log.Errorf("error deleting user token: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// redirect to domains
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *Api) domains(w http.ResponseWriter, r *http.Request) {
	username, _, err := a.getUsernameAndToken(r)
	if err != nil {
		log.Errorf("unable to get username from request: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if username == "" {
		http.Error(w, "unable to get user", http.StatusUnauthorized)
		return
	}

	domains, err := a.manager.Domains(username)
	if err != nil {
		log.Errorf("error getting domains: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if domains == nil {
		domains = []*manager.Domain{}
	}

	if err := json.NewEncoder(w).Encode(domains); err != nil {
		log.Errorf("error serializing domains: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) addDomain(w http.ResponseWriter, r *http.Request) {
	username, _, err := a.getUsernameAndToken(r)
	if err != nil {
		log.Errorf("unable to get username from request: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if username == "" {
		http.Error(w, "unable to get user", http.StatusUnauthorized)
		return
	}

	var domain *manager.Domain

	if err := json.NewDecoder(r.Body).Decode(&domain); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := a.manager.AddSubdomain(username, domain); err != nil {
		log.Errorf("error adding domain: prefix=%s err=%s", domain.Prefix, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Infof("created domain: prefix=%s username=%s", domain.Prefix, username)
}

func (a *Api) removeDomain(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	prefix := vars["prefix"]

	username, _, err := a.getUsernameAndToken(r)
	if err != nil {
		log.Errorf("unable to get username from request: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if username == "" {
		http.Error(w, "unable to get user", http.StatusUnauthorized)
		return
	}

	if err := a.manager.RemoveSubdomain(username, prefix); err != nil {
		log.Errorf("error removing subdomain: err=%s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Infof("removed domain: prefix=%s username=%s", prefix, username)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Api) getIP(w http.ResponseWriter, r *http.Request) {
	addr := strings.Split(r.RemoteAddr, ":")
	w.Write([]byte(addr[0]))
}

func (a *Api) Run() error {
	globalMux := http.NewServeMux()

	authRouter := mux.NewRouter()
	authRouter.HandleFunc("/auth/login", a.login).Methods("GET")
	authRouter.HandleFunc("/auth/logout", a.logout).Methods("GET")
	authRouter.HandleFunc("/auth/callback", a.authCallback).Methods("GET")

	apiRouter := mux.NewRouter()

	apiRouter.Handle("/api/domains", a.authRequiredMiddleware(http.HandlerFunc(a.domains))).Methods("GET")
	apiRouter.Handle("/api/domains", a.authRequiredMiddleware(http.HandlerFunc(a.addDomain))).Methods("POST")
	apiRouter.Handle("/api/domains/{prefix:.*}", a.authRequiredMiddleware(http.HandlerFunc(a.removeDomain))).Methods("DELETE")
	apiRouter.HandleFunc("/api/ip", a.getIP).Methods("GET")

	//globalMux.Handle("/api/", apiRouter)
	globalMux.Handle("/api/", apiRouter)
	globalMux.Handle("/auth/", authRouter)

	// global handler
	globalMux.Handle("/", http.FileServer(http.Dir("static")))

	s := &http.Server{
		Addr:    a.listenAddr,
		Handler: context.ClearHandler(globalMux),
	}

	if err := s.ListenAndServe(); err != nil {
		return err
	}

	return http.ListenAndServe(a.listenAddr, context.ClearHandler(globalMux))
}
