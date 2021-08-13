package cryptowrapper

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/gob"

	"github.com/aead/ecdh"
)

const rsaBitSize = 2048

var sendLabel = make([]byte, 32)

func GenerateKeys() *rsa.PrivateKey {
	pk, err := rsa.GenerateKey(rand.Reader, rsaBitSize)
	if err != nil {
		panic("no key generation possible")
	}
	return pk
}
func EncryptAsymmetric(data []byte, publicKey rsa.PublicKey) ([]byte, error) {
	encrypted, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, &publicKey, data, sendLabel)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func DecryptAsymetric(message []byte, privateKey rsa.PrivateKey) ([]byte, error) {
	decrypted, err := rsa.DecryptOAEP(crypto.SHA256.New(), rand.Reader, &privateKey, message, sendLabel)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
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

func EncodeECDHPoint(point ecdh.Point) []byte {
	b := bytes.Buffer{}
	enc := gob.NewEncoder(&b)
	enc.Encode(point)
	return b.Bytes()
}

func DecodeECDHPoint(ecdhPoint []byte, output *ecdh.Point) {
	b := bytes.NewBuffer(ecdhPoint)
	dec := gob.NewDecoder(b)
	dec.Decode(output)

}

func EncodeRSAPublicKey(publicKey rsa.PublicKey) []byte {
	b := bytes.Buffer{}
	enc := gob.NewEncoder(&b)
	enc.Encode(publicKey)
	return b.Bytes()
}

func DecodeRSAPublicKey(in []byte, out *rsa.PublicKey) {
	b := bytes.NewBuffer(in)
	dec := gob.NewDecoder(b)
	dec.Decode(out)
}
