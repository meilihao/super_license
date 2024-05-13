package key

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"

	"github.com/pkg/errors"
)

const (
	HeaderComment = "Comment"
	HeaderSalt    = "Salt"
)

func EncodePubToPem(pub any) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, errors.Wrap(err, "marshal public key")
	}

	pubPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	buf := bytes.NewBuffer(nil)

	if err = pem.Encode(buf, pubPEM); err != nil {
		return nil, errors.Wrap(err, "encode public key to pem")
	}

	return buf.Bytes(), nil
}

func ParsePubFromPem(pubPEM []byte) (any, error) {
	if len(pubPEM) == 0 {
		return nil, errors.New("no pem content")
	}

	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse DER encoded public key")
	}

	switch pub.(type) {
	case *rsa.PublicKey, ed25519.PublicKey:
	default:
		return nil, errors.New("unknown type of public key")
	}

	return pub, nil
}

func EncodePrivToPem(priv any, password, salt []byte, comment string) ([]byte, error) {
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, errors.Wrap(err, "marshal private key")
	}

	// Encode the private key to the PEM format
	privPEM := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}
	if comment != "" {
		privPEM.Headers = map[string]string{
			"Comment": comment,
		}
	}

	if len(password) != 0 {
		privPEM.Type = "ENCRYPTED PRIVATE KEY"

		privPEM, err = x509.EncryptPEMBlock(rand.Reader, privPEM.Type, privPEM.Bytes, password, x509.PEMCipherAES256)
		if err != nil {
			return nil, errors.Wrap(err, "encrypt private key by pem")
		}
		privPEM.Headers[HeaderSalt] = hex.EncodeToString(salt)
		if comment != "" {
			privPEM.Headers["Comment"] = comment
		}
	}

	buf := bytes.NewBuffer(nil)

	if err = pem.Encode(buf, privPEM); err != nil {
		return nil, errors.Wrap(err, "encode private key to pem")
	}

	return buf.Bytes(), nil
}

func ParsePrivFromPem(privPEM []byte, password []byte) (any, error) {
	if len(privPEM) == 0 {
		return nil, errors.New("no pem content")
	}

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

		salt, err := hex.DecodeString(block.Headers[HeaderSalt])
		if err != nil {
			return nil, errors.New("missing salt")
		}

		if password, _, err = GenerateKDFKey(password, salt); err != nil {
			return nil, errors.Wrap(err, "generate kdf key")
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
	case *rsa.PrivateKey, ed25519.PrivateKey:
	default:
		return nil, errors.New("unknown type of private key")
	}

	return priv, nil
}
