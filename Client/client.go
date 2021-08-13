package client

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	grpcnode "DHE/grpc"
)

type NetworkElement interface {
	Register(element NetworkElement)
	GetAddress() string
}

type Client struct {
	id int32
	address          string
	privateKey       rsa.PrivateKey
	publicKey        rsa.PublicKey
	publicKeys       map[string]rsa.PublicKey

	server *grpcnode.GRPCServer
	client *grpcnode.GRPCClient
}

func New(id int32,address string, receiver []string) (c *Client, err error) {
	c = new(Client)
	pk, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return nil, fmt.Errorf("error during creation of client at address %v", address)
	}

	c.id=id
	c.privateKey = *pk
	c.publicKey = pk.PublicKey

	c.publicKeys = map[string]rsa.PublicKey{}
	c.address = address

	c.server = grpcnode.NewServer(address, c.publicKey, c.privateKey)
	c.server.Listen()


	c.client = grpcnode.NewClient(c.publicKey, c.privateKey)

	return c, nil
}


func (c *Client) Register(element NetworkElement) {

	address,pubKey :=c.client.InitExchange(c.id,element.GetAddress())
	c.publicKeys[address]= pubKey

	log.Printf("neighbour %v added at %v. Initiating key exchange.", element.GetAddress(), c.address)
}

func (c *Client) GetAddress() string {
	log.Printf("get address called at %v", c.address)
	return c.address
}


func (c *Client) SendMessage(address string)  {
c.client.SendMessage(int32(c.id),address,c.publicKeys[address])
}
