package manager

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/garyburd/redigo/redis"
	"github.com/shipyard/shpd/auth"
	"github.com/shipyard/shpd/utils"
)

const (
	accountsKey   = "accounts"
	authTokensKey = "authtokens"
	defaultExpire = 86400 * 14 // two weeks
)

var (
	ErrInvalidToken = errors.New("invalid token")
)

type Manager struct {
	pool *redis.Pool
}

func NewManager(addr string, password string) (*Manager, error) {
	log.Debugf("connecting: addr=%s", addr)
	pool := &redis.Pool{
		MaxIdle:     3,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", addr)
			if err != nil {
				return nil, err
			}
			if password != "" {
				if _, err := c.Do("AUTH", password); err != nil {
					c.Close()
					return nil, err
				}
			}
			return c, err
		},
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			_, err := c.Do("PING")
			return err
		},
	}

	return &Manager{
		pool: pool,
	}, nil
}

func (m *Manager) Account(username string) (*auth.Account, error) {
	conn := m.pool.Get()
	defer conn.Close()

	key := fmt.Sprintf("%s:%s", accountsKey, username)
	d, err := redis.String(conn.Do("GET", key))
	if err == redis.ErrNil {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	data := bytes.NewBufferString(d)

	var account *auth.Account
	if err := json.Unmarshal(data.Bytes(), &account); err != nil {
		return nil, err
	}

	return account, nil
}

func (m *Manager) SaveAccount(account *auth.Account) error {
	conn := m.pool.Get()
	defer conn.Close()

	// convert password to hash
	passwd, err := utils.HashPassword(account.Password)
	if err != nil {
		return err
	}

	account.Password = string(passwd)

	data, err := json.Marshal(account)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("%s:%s", accountsKey, account.Username)
	if _, err := conn.Do("SET", key, string(data)); err != nil {
		return err
	}

	return nil

}

func (m *Manager) Authenticate(username, password string) bool {
	account, err := m.Account(username)
	if err != nil {
		return false
	}

	if account == nil {
		return false
	}

	return utils.Authenticate(account.Password, password)
}

func (m *Manager) GenerateToken(username string) (*auth.AuthToken, error) {
	conn := m.pool.Get()
	defer conn.Close()

	t, err := utils.GenerateToken()
	if err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%s:%s", authTokensKey, username)
	if _, err := conn.Do("SET", key, t); err != nil {
		return nil, err
	}

	// set token to expire after default expire
	if _, err := conn.Do("EXPIRE", key, defaultExpire); err != nil {
		return nil, err
	}
	return &auth.AuthToken{
		Username: username,
		Token:    t,
	}, nil
}

func (m *Manager) ValidateToken(username, token string) error {
	conn := m.pool.Get()
	defer conn.Close()

	key := fmt.Sprintf("%s:%s", authTokensKey, username)
	t, err := redis.String(conn.Do("GET", key))
	if err != nil {
		return err
	}

	if token == t {
		return nil
	}

	return ErrInvalidToken
}
