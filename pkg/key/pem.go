package key

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
)

func ParsePubFromPem(pubPEM []byte) (any, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse DER encoded public key")
	}

	switch pub.(type) {
	case *rsa.PublicKey, *ed25519.PublicKey:
	default:
		return nil, errors.New("unknown type of public key")
	}

	return pub, nil
}

func ParsePrivFromPem(privPEM []byte, password []byte) (any, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("parse PEM block containing the private key")
	}

	var err error
	privBytes := block.Bytes

	if x509.IsEncryptedPEMBlock(block) {
		if len(password) == 0 {
			return nil, errors.New("missing password")
		}

		privBytes, err = x509.DecryptPEMBlock(block, password)
		if err != nil {
			return nil, errors.Wrap(err, "decrypt private key by pem")
		}
	}

	priv, err := x509.ParsePKCS8PrivateKey(privBytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse DER encoded private key")
	}

	switch priv.(type) {
	case *rsa.PrivateKey, *ed25519.PrivateKey:
	default:
		return nil, errors.New("unknown type of private key")
	}

	return priv, nil
}
