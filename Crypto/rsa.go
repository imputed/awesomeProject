package cryptowrapper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
)

const rsaBitSize = 2048

func GenerateKeys() *rsa.PrivateKey {
	pk, err := rsa.GenerateKey(rand.Reader, rsaBitSize)
	if err != nil {
		panic("no key generation possible")
	}
	return pk
}

func EncryptSymmetric(plaintext, secret []byte) (ciphertext []byte) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, 12)
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	return aesgcm.Seal(nil, nonce, plaintext, nil)

}

func DecryptSymmetric(ciphertext, secret []byte) (plaintext []byte) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, 12)
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	plaintext, err = aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext

}
