package key

import (
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

func GenerateKDFKey(p string) ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	dk := pbkdf2.Key([]byte(p), salt, 1, 32, sha256.New)
	return dk, nil
}
