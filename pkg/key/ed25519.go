package key

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/pkg/errors"
)

type GenerateEd25519Req struct {
	Password  string
	_Password []byte
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
		if r._Password, err = GenerateKDFKey(r.Password); err != nil {
			errors.Wrap(err, "generate kdf key")
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

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return errors.Wrap(err, "marshal ed25519 private key")
	}

	// Encode the private key to the PEM format
	privPEM := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}
	if r.Commont != "" {
		privPEM.Headers = map[string]string{
			"Comment": r.Commont,
		}
	}

	if len(r._Password) != 0 {
		privPEM, err = x509.EncryptPEMBlock(rand.Reader, privPEM.Type, privPEM.Bytes, r._Password, x509.PEMCipherAES256)
		if err != nil {
			return errors.Wrap(err, "encrypt private key by pem")
		}
	}

	privFile, err := os.Create(r.Fpath + ".pem")
	if err != nil {
		return errors.Wrap(err, "creating private key file")
	}

	pem.Encode(privFile, privPEM)
	privFile.Close()

	// Encode the public key to the PEM format
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return errors.Wrap(err, "marshal ed25519 public key")
	}

	pubPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	pubFile, err := os.Create(r.Fpath + ".pub.pem")
	if err != nil {
		return errors.Wrap(err, "creating public key file")
	}

	pem.Encode(pubFile, pubPEM)
	pubFile.Close()

	fmt.Println("ed25519 key pair generated successfully!")

	return nil
}
