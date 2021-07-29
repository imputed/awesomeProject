package client

import (
	cryptoWrapper "DHE/Crypto"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"github.com/aead/ecdh"
	"log"
)

type Message struct {
	pubKey    rsa.PublicKey
	signature []byte
	data      []byte
}

type NetworkElement interface {
	Register(element NetworkElement)
	Respond(message Message)
	GetAddress() string
	SetExchangeObject(object ExchangeObject, element NetworkElement)
	SetPublicKey(key rsa.PublicKey, element NetworkElement)
	keyExchangeI(c NetworkElement, curve ecdh.KeyExchange, key crypto.PublicKey) error
	keyExchangeIII(c NetworkElement, ciphertext []byte)
	keyExchangeII(c NetworkElement, exchange ecdh.KeyExchange, key crypto.PublicKey) error
	keyExchangeIV(c NetworkElement, ciphertext []byte)
}

type ExchangeObject struct {
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey
	secret     []byte
}

type Client struct {
	address         string
	privateKey      rsa.PrivateKey
	publicKey       rsa.PublicKey
	neighbours      []NetworkElement
	publicKeys      map[NetworkElement]rsa.PublicKey
	exchangeObjects map[NetworkElement]ExchangeObject
}

func New(address string) (c *Client, err error)  {
	c = new(Client)
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("error during creation of client at address v%",address)
	}
	c.privateKey = *pk
	c.publicKey = pk.PublicKey
	c.exchangeObjects = map[NetworkElement]ExchangeObject{}
	c.publicKeys = map[NetworkElement]rsa.PublicKey{}
	c.address = address
	log.Printf("client at address v% created",address)
	return c,nil
}

func (c *Client) Register(element NetworkElement) {
	c.neighbours = append(c.neighbours, element)
	log.Printf("neighbour %v added at v%",element.GetAddress(),c.address)
}

func (c *Client) GetAddress() string {
	return c.address
	log.Printf("get address called at v%",c.address)
}

func (c *Client) SetExchangeObject(object ExchangeObject, element NetworkElement) {
	c.exchangeObjects[element] = object
}

func (c *Client) SetPublicKey(key rsa.PublicKey, element NetworkElement) {
	c.publicKeys[element] = key
}


func (c *Client) Respond(element Message) {
	digest := sha256.Sum256(element.data)
	verifyErr := rsa.VerifyPKCS1v15(&element.pubKey, crypto.SHA256, digest[:], element.signature)

	if verifyErr != nil {
		fmt.Printf("Verification failed: %s", verifyErr)
	} else {
		log.Printf("Correct!, %v\n", string(element.data))
	}
}

func (c *Client) Broadcast() error {
	data := []byte("Hello, World!")

	digest := sha256.Sum256(data)
	signature, signErr := rsa.SignPKCS1v15(rand.Reader, &c.privateKey, crypto.SHA256, digest[:])
	if signErr != nil {
		return signErr
	}
	m := Message{data: data, signature: signature, pubKey: c.privateKey.PublicKey}
	for i := 0; i < len(c.neighbours); i++ {
		n := c.neighbours[i]
		n.Respond(m)
	}
	return nil
}
func (c *Client) InitKeyExchange(element NetworkElement) (err error) {
	curve := ecdh.Generic(elliptic.P256())
	exchangeObject := ExchangeObject{}
	exchangeObject.privateKey, exchangeObject.publicKey, err = curve.GenerateKey(rand.Reader)
	if err != nil {
		log.Println("failed to generate keys for key exchange")
		return err
	}
	c.SetExchangeObject(exchangeObject,element)
	err = element.keyExchangeI(c, curve, exchangeObject.publicKey)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) keyExchangeI(element NetworkElement, exchange ecdh.KeyExchange, publicKey crypto.PublicKey) (err error) {
	exchangeObject := ExchangeObject{}
	exchangeObject.privateKey, exchangeObject.publicKey, err = exchange.GenerateKey(rand.Reader)
	if err != nil {
		log.Println("keys could not be generated")
		return err
	}
	if err := exchange.Check(publicKey); err != nil {
		log.Println("public key is not on the curve")
		return err
	}
	secret := exchange.ComputeSecret(exchangeObject.privateKey, publicKey)
	exchangeObject.secret = secret
	c.SetExchangeObject(exchangeObject, element)
	err = element.keyExchangeII(c, exchange, exchangeObject.publicKey)
	if err != nil {
		log.Println("keyExchangeII returned error")
		return err
	}
	return nil
}

func (c *Client) keyExchangeII(element NetworkElement, exchange ecdh.KeyExchange, publicKey crypto.PublicKey) (err error) {
	if err := exchange.Check(publicKey); err != nil {
		log.Println("public key is not on the curve")
		return err
	}
	secret := exchange.ComputeSecret(c.exchangeObjects[element].privateKey, publicKey)
	exchangeObject := c.exchangeObjects[element]
	exchangeObject.secret = secret
	c.SetExchangeObject(exchangeObject, element)
	plaintext := x509.MarshalPKCS1PublicKey(&c.publicKey)
	ciphertext := cryptoWrapper.EncryptSymmetric(plaintext, secret)
	element.keyExchangeIII(c, ciphertext)
	return nil
}

func (c *Client) keyExchangeIII(element NetworkElement, ciphertext []byte) {
	key, err := x509.ParsePKCS1PublicKey(cryptoWrapper.DecryptSymmetric(ciphertext, c.exchangeObjects[element].secret))
	if err != nil {
		panic(err.Error())
	}
	c.SetPublicKey(*key,element)
	log.Printf("%v got public key from %v:\n %v", c.address, element.GetAddress(), key)
	plaintext := x509.MarshalPKCS1PublicKey(&c.publicKey)
	ciphertext = cryptoWrapper.EncryptSymmetric(plaintext, c.exchangeObjects[element].secret)
	element.keyExchangeIV(c, ciphertext)
}

func (c *Client) keyExchangeIV(element NetworkElement, ciphertext []byte) {
	key, err := x509.ParsePKCS1PublicKey(cryptoWrapper.DecryptSymmetric(ciphertext, c.exchangeObjects[element].secret))
	if err != nil {
		panic(err.Error())
	}
	c.SetPublicKey(*key,element)
	log.Printf("%v got public key from %v:\n %v", c.address, element.GetAddress(), key)

}

