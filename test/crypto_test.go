package main

import (
	"DHE/Crypto"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"log"
	"testing"
)

func TestKeyGeneration(t *testing.T) {
	pk := cryptowrapper.GenerateKeys()
	if pk == nil {
		t.Fatalf("no rsa keys were generated ")
	}
	message := []byte("Hello, World")
	log.Println("original bytes:  ", message)
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&pk.PublicKey,
		message,
		nil)
	if err != nil {
		t.Fatalf("no encryption possible")
	}
	log.Println("encrypted bytes: ", encryptedBytes)

	decryptedBytes, err := pk.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("no decryption possible")
	}
	log.Println("decrypted bytes: ", decryptedBytes)

	if string(decryptedBytes) != string(message) {
		t.Fatalf("encryption and decryption do not work")
	}
}

func TestSymmetricEncryption(t *testing.T) {
	teststring := []byte("Test der Encryption und Decryption")
	bit := make([]byte, 32)
	enc := cryptowrapper.EncryptSymmetric(teststring, bit)
	dec := cryptowrapper.DecryptSymmetric(enc, bit)
	if string(teststring) != string(dec) {
		t.Fatalf("encryption and decryption do not work")
	}
}

func TestAsymmetricEncryption(t *testing.T) {
	testString := []byte("Test der Encryption und Decryption")
	pk := cryptowrapper.GenerateKeys()

	enc, _ := cryptowrapper.EncryptAsymmetric(testString, pk.PublicKey)
	dec, _ := cryptowrapper.DecryptAsymetric(enc, *pk)
	for i := 0; i < len(testString); i++ {
		if dec[i] != testString[i] {
			t.Errorf("Assymmetric Encryption not working")
		}
	}
}
