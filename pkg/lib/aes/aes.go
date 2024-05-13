package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// AesGcmEncrypt takes an encryption key and a plaintext string and encrypts it with AES256 in GCM mode, which provides authenticated encryption. Returns the ciphertext and the used nonce.
// openssl_encrypt
func AesGcmEncrypt(key []byte, plaintextBytes []byte) (ciphertext, nonce []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce = make([]byte, aesgcm.NonceSize()) // 12
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	ciphertext = aesgcm.Seal(nil, nonce, plaintextBytes, nil)

	return
}

// AesGcmDecrypt takes an decryption key, a ciphertext and the corresponding nonce and decrypts it with AES256 in GCM mode. Returns the plaintext string.
// openssl_decrypt
func AesGcmDecrypt(key, ciphertext, nonce []byte) (plaintextBytes []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintextBytes, err = aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return
}
