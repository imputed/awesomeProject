package grpcnode

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"net"

	cryptoWrapper "DHE/Crypto"
	pb "DHE/grpc/pb"
	"github.com/aead/ecdh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

type GRPCClient struct {
	context      context.Context
	address      string
	privateKey   rsa.PrivateKey
	publicKey    rsa.PublicKey
	tlsPrivKey   []byte
	tlsPubKey    ecdh.Point
	encodedTLSPK []byte
	curve        ecdh.KeyExchange
}

type clientAddress struct {
	address string
	port    string
}

func (c clientAddress) Network() string {
	return c.address
}
func (c clientAddress) String() string {
	return c.port
}

func NewClient(publicKey rsa.PublicKey, privateKey rsa.PrivateKey) *GRPCClient {
	var err error

	a := net.IP{127, 0, 0, 1}

	c := GRPCClient{}
	addr := net.TCPAddr{
		IP:   a,
		Port: 1,
		Zone: "",
	}
	p := peer.Peer{
		Addr:     &addr,
		AuthInfo: nil,
	}
c.context = peer.NewContext(context.Background(),&p)
	c.curve = ecdh.Generic(elliptic.P256())
	c.privateKey = privateKey
	c.publicKey = publicKey

	curve := ecdh.Generic(elliptic.P256())

	privKey, pubKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Errorf("error in creating of tls keys")
	}

	c.tlsPrivKey = privKey.([]byte)
	c.tlsPubKey = pubKey.(ecdh.Point)
	c.encodedTLSPK = cryptoWrapper.EncodeECDHPoint(c.tlsPubKey)
	return &c
}

func (c *GRPCClient) InitExchange(id int32, address string) (string, rsa.PublicKey) {
	var (
		decodedPublicKey     rsa.PublicKey
		receivedTlSPublicKey ecdh.Point
		response             pb.KeyExchangeMessage
	)

	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	defer conn.Close()
	if err != nil {
		log.Fatalf("cannot connect: %v", err)
	}

	client := pb.NewCommunicationClient(conn)

	stream, err := client.KeyExchangeChat(c.context)
	if err != nil {
		log.Fatalf("%v.RouteChat(_) = _, %v", client, err)
	}

	stream.Send(&pb.KeyExchangeMessage{Id: int32(id),  ExchangePublicKey: c.encodedTLSPK})

	waitc := make(chan struct{})

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			// read done.
			close(waitc)
			return "", rsa.PublicKey{}
		}
		if err != nil {
			log.Fatalf("Failed to receive a note : %v", err)
		}
		response = pb.KeyExchangeMessage{ExchangePublicKey: in.ExchangePublicKey, EncryptedPublicKey: in.EncryptedPublicKey}
		break

	}

	cryptoWrapper.DecodeECDHPoint(response.ExchangePublicKey, &receivedTlSPublicKey)
	if err := c.curve.Check(receivedTlSPublicKey); err != nil {
		fmt.Println("received public key is not on the curve")
	}

	secret := c.curve.ComputeSecret(c.tlsPrivKey, receivedTlSPublicKey)
	decryptedPublicKey := cryptoWrapper.DecryptSymmetric(response.EncryptedPublicKey, secret)
	cryptoWrapper.DecodeRSAPublicKey(decryptedPublicKey, &decodedPublicKey)

	log.Printf("%v: Got PublicKey %v from %v", c.address, decodedPublicKey, conn.Target())

	stream.Send(&pb.KeyExchangeMessage{EncryptedPublicKey: cryptoWrapper.EncryptSymmetric(cryptoWrapper.EncodeRSAPublicKey(c.publicKey), secret)})
	stream.CloseSend()
	conn.Close()
	return address, decodedPublicKey
}

func (c *GRPCClient) SendMessage(id int32, address string, publicKey rsa.PublicKey) {
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	defer conn.Close()
	if err != nil {
		log.Fatalf("cannot connect: %v", err)
	}

	client := pb.NewCommunicationClient(conn)
	text, _ := cryptoWrapper.EncryptAsymmetric([]byte("Hello!"), publicKey)

	m := pb.Message{Id: int32(id), Text: text}
	log.Printf("Send Message \n   Encrypted %v \n   Decrypted: %v", text,"Hello!")


	r, err := client.SendMessage(c.context, &m)
	dec, _ := cryptoWrapper.DecryptAsymetric(r.Text, c.privateKey)
	log.Printf("Received Message from %v: \n   Encrypted %v \n   Decrypted: %v, %v",conn.Target(), r.Text, dec,string(dec))

}
