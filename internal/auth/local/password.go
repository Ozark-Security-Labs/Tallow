package local

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const bcryptPrefix = "bcrypt$"

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return bcryptPrefix + string(hash), nil
}

func VerifyPassword(encoded, password string) bool {
	if !strings.HasPrefix(encoded, bcryptPrefix) {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(strings.TrimPrefix(encoded, bcryptPrefix)), []byte(password)) == nil
}
