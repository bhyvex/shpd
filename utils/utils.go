package utils

import (
	"strings"

	uuid "github.com/nu7hatch/gouuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), -1)
}

func Authenticate(hash, password string) bool {
	p := []byte(password)
	h := []byte(hash)
	if err := bcrypt.CompareHashAndPassword(h, p); err != nil {
		return false
	}

	return true
}

func GenerateToken() (string, error) {
	u, err := uuid.NewV4()
	if err != nil {
		return "", err
	}

	t := strings.Replace(u.String(), "-", "", -1)
	return t, nil
}
