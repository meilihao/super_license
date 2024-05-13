package key

import (
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

func GenerateKDFKey(p, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}

	dk := pbkdf2.Key(p, salt, 1, 32, sha256.New)
	return dk, salt, nil
}
