package key

import (
	"github.com/pkg/errors"
)

const (
	TypeEd25519 = "ed25519"
	TypeRSA     = "rsa"
)

var (
	ErrTypeInvalid    = errors.New("invalid key type")
	ErrBitsInvalidRSA = errors.New("invalid key bits: 3072, 4096, default is 4096")
	ErrKeyExist       = errors.New("key exist")
)
