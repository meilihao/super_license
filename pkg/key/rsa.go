package key

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/pkg/errors"
)

type GenerateRSAReq struct {
	Bits      int
	Password  string
	_Password []byte
	_Salt     []byte
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
		if r._Password, r._Salt, err = GenerateKDFKey([]byte(r.Password), nil); err != nil {
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

	// Encode the private key to the PEM format
	privBuf, err := EncodePrivToPem(priv, r._Password, r._Salt, r.Commont)
	if err != nil {
		return errors.Wrap(err, "generate private pem")
	}

	privFile, err := os.Create(r.Fpath + ".pem")
	if err != nil {
		return errors.Wrap(err, "creating private key file")
	}
	privFile.Write(privBuf)
	privFile.Close()

	// Encode the public key to the PEM format
	pubBuf, err := EncodePubToPem(pub)
	if err != nil {
		return errors.Wrap(err, "generate public pem")
	}

	pubFile, err := os.Create(r.Fpath + ".pub.pem")
	if err != nil {
		return errors.Wrap(err, "creating public key file")
	}
	pubFile.Write(pubBuf)
	pubFile.Close()

	fmt.Println("RSA key pair generated successfully!")

	return nil
}
