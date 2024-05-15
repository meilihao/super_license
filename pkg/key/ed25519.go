package key

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/pkg/errors"
)

type GenerateEd25519Req struct {
	Password  string
	_Password []byte
	_Salt     []byte
	Fpath     string
	Commont   string
}

func (r *GenerateEd25519Req) Valid() error {
	if r.Fpath != "" {
		if _, err := os.Stat(r.Fpath); !errors.Is(err, os.ErrNotExist) {
			return ErrKeyExist
		}
	} else {
		r.Fpath = "id_ed25519"
	}

	if r.Password != "" {
		var err error
		if r._Password, r._Salt, err = GenerateKDFKey([]byte(r.Password), nil); err != nil {
			return err
		}
	}

	return nil
}

func GenerateEd25519(r *GenerateEd25519Req) error {
	var err error
	if err = r.Valid(); err != nil {
		return err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.Wrap(err, "generating ed25519 private key")
	}

	// Encode the private key to the PEM format
	privBuf, err := EncodePrivToPem(priv, r._Password, r._Salt, r.Commont)
	if err != nil {
		return errors.Wrap(err, "generate private pem")
	}

	privFile, err := os.Create(r.Fpath + ".pem")
	if err != nil {
		return errors.Wrap(err, "creating private key file")
	}
	defer privFile.Close()

	if _, err = privFile.Write(privBuf); err != nil {
		return errors.Wrap(err, "write private key file")
	}

	// Encode the public key to the PEM format
	pubBuf, err := EncodePubToPem(pub)
	if err != nil {
		return errors.Wrap(err, "generate public pem")
	}

	pubFile, err := os.Create(r.Fpath + ".pub.pem")
	if err != nil {
		return errors.Wrap(err, "creating public key file")
	}
	defer pubFile.Close()

	if _, err = pubFile.Write(pubBuf); err != nil {
		return errors.Wrap(err, "write public key file")
	}

	fmt.Println("ed25519 key pair generated successfully!")

	return nil
}
