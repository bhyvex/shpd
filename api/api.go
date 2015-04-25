package api

import (
	"encoding/json"
	"net/http"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/shipyard/shpd/auth"
	"github.com/shipyard/shpd/manager"
)

type Api struct {
	listenAddr string
	manager    *manager.Manager
}

type Credentials struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func NewApi(listen string, addr string, password string) (*Api, error) {
	mgr, err := manager.NewManager(addr, password)
	if err != nil {
		return nil, err
	}

	return &Api{
		listenAddr: listen,
		manager:    mgr,
	}, nil
}

func (a *Api) authRequiredMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHeader := r.Header.Get("X-Access-Token")
		parts := strings.Split(tokenHeader, ":")

		if len(parts) != 2 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		username := parts[0]
		token := parts[1]

		if err := a.manager.ValidateToken(username, token); err == nil {
			next.ServeHTTP(w, r)
			return
		}

		log.Warnf("unauthorized request: username=%s token=%s addr=%s", username, token, r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func (a *Api) login(w http.ResponseWriter, r *http.Request) {
	var creds *Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		log.Warnf("error getting login credentials: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !a.manager.Authenticate(creds.Username, creds.Password) {
		log.Warnf("invalid login: username=%s addr=%s", creds.Username, r.RemoteAddr)
		http.Error(w, "invalid username/password", http.StatusUnauthorized)
		return
	}

	token, err := a.manager.GenerateToken(creds.Username)
	if err != nil {
		log.Errorf("error generating token: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(token); err != nil {
		log.Errorf("error serializing auth token: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Debugf("user login: username=%s addr=%s", creds.Username, r.RemoteAddr)
}

func (a *Api) signup(w http.ResponseWriter, r *http.Request) {
	var account *auth.Account
	if err := json.NewDecoder(r.Body).Decode(&account); err != nil {
		log.Errorf("error getting signup account: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// check for existing user
	acct, err := a.manager.Account(account.Username)
	if err != nil {
		log.Errorf("error getting account: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// user already exists
	if acct != nil {
		http.Error(w, "user already exists", http.StatusBadRequest)
		return
	}

	// create account
	if err := a.manager.SaveAccount(account); err != nil {
		log.Errorf("error saving account: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Infof("signup: username=%s email=%s", account.Username, account.Email)
}

func (a *Api) domains(w http.ResponseWriter, r *http.Request) {
	// TODO: pull from manager
	type Domain struct {
		Name string
	}

	domains := []Domain{
		{
			Name: "foo.com",
		},
		{
			Name: "bar.com",
		},
	}

	if err := json.NewEncoder(w).Encode(domains); err != nil {
		log.Errorf("error serializing domains: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) Run() error {
	globalMux := http.NewServeMux()

	authRouter := mux.NewRouter()
	authRouter.HandleFunc("/auth/login", a.login).Methods("POST")
	authRouter.HandleFunc("/auth/signup", a.signup).Methods("POST")

	apiRouter := mux.NewRouter()

	apiRouter.Handle("/api/domains", a.authRequiredMiddleware(http.HandlerFunc(a.domains)))

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
