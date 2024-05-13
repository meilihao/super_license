package key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/pkg/errors"
)

type GenerateRSAReq struct {
	Bits      int
	Password  string
	_Password []byte
	Fpath     string
	Commont   string
}

func (r *GenerateRSAReq) Valid() error {
	if !(r.Bits == 3072 || r.Bits == 4096) {
		return ErrBitsInvalidRSA
	}

	if r.Fpath != "" {
		if _, err := os.Stat(r.Fpath); !errors.Is(err, os.ErrNotExist) {
			return ErrKeyExist
		}
	} else {
		r.Fpath = "id_rsa"
	}

	if r.Password != "" {
		var err error
		if r._Password, err = GenerateKDFKey(r.Password); err != nil {
			errors.Wrap(err, "generate kdf key")
		}
	}

	return nil
}

func GenerateRSA(r *GenerateRSAReq) error {
	var err error
	if err = r.Valid(); err != nil {
		return err
	}

	priv, err := rsa.GenerateKey(rand.Reader, r.Bits)
	if err != nil {
		return errors.Wrap(err, "generating RSA private key")
	}
	pub := &priv.PublicKey

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return errors.Wrap(err, "marshal RSA private key")
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
		return errors.Wrap(err, "marshal RSA public key")
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

	fmt.Println("RSA key pair generated successfully!")

	return nil
}
