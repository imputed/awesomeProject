package grpcnode

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"net"

	cryptoWrapper "DHE/Crypto"
	communication "DHE/grpc/pb"
	"github.com/aead/ecdh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

type GRPCServer struct {
	port string

	tlsPrivKey      crypto.PrivateKey
	tlsPublicKey    ecdh.Point
	privateKey      rsa.PrivateKey
	publicKey       rsa.PublicKey
	keyExchange     ecdh.KeyExchange
	exchangeObjects map[net.Addr]ExchangeObject
	publicKeys      map[int32]rsa.PublicKey
	communication.UnimplementedCommunicationServer
}

type ExchangeObject struct {
	publicKey crypto.PublicKey
	secret    []byte
}

func NewServer(port string, publicKey rsa.PublicKey, privateKey rsa.PrivateKey) *GRPCServer {
	server := GRPCServer{}
	server.exchangeObjects = map[net.Addr]ExchangeObject{}
	server.publicKeys = map[int32]rsa.PublicKey{}
	server.port = port
	server.keyExchange = ecdh.Generic(elliptic.P256())
	server.publicKey = publicKey
	server.privateKey = privateKey

	privateTLSKey, publicTLSKey, _ := server.keyExchange.GenerateKey(rand.Reader)
	server.tlsPrivKey = privateTLSKey
	server.tlsPublicKey = publicTLSKey.(ecdh.Point)

	return &server
}

func (s *GRPCServer) KeyExchangeChat(stream communication.Communication_KeyExchangeChatServer) error {
	var (
		receivedPubTlsKey ecdh.Point
	)

	if p, ok := peer.FromContext(stream.Context()); ok {
		for {
			in, err := stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				continue
			}

			if in.EncryptedPublicKey == nil && in.ExchangePublicKey != nil {

				cryptoWrapper.DecodeECDHPoint(in.ExchangePublicKey, &receivedPubTlsKey)

				if err := s.keyExchange.Check(receivedPubTlsKey); err != nil {
					log.Println("received public key is not on the curve")
					return err
				}

				secret := s.keyExchange.ComputeSecret(s.tlsPrivKey, receivedPubTlsKey)

				s.exchangeObjects[p.Addr] = ExchangeObject{publicKey: receivedPubTlsKey, secret: secret}
				TlsPublicKey := cryptoWrapper.EncodeECDHPoint(s.tlsPublicKey)
				bufferedPublicKey := cryptoWrapper.EncodeRSAPublicKey(s.publicKey)
				reply := communication.KeyExchangeMessage{ExchangePublicKey: TlsPublicKey, EncryptedPublicKey: cryptoWrapper.EncryptSymmetric(bufferedPublicKey, secret)}
				if err := stream.Send(&reply); err != nil {
					log.Printf("send error %v", err)
				}

				log.Printf("%v: sent reply to %v", s.port, p.Addr)

			} else if in.EncryptedPublicKey != nil && in.ExchangePublicKey == nil {
				secret := s.exchangeObjects[p.Addr].secret
				decryptedPublicKey := cryptoWrapper.DecryptSymmetric(in.GetEncryptedPublicKey(), secret)
				var decodedPublicKey rsa.PublicKey
				cryptoWrapper.DecodeRSAPublicKey(decryptedPublicKey, &decodedPublicKey)
				s.publicKeys[in.Id] = decodedPublicKey
				log.Printf("%v: Got PublicKey %v from %v", s.port, decodedPublicKey, p.Addr)
			}
		}
	}
	return nil
}
func (s *GRPCServer) SendMessage(c context.Context, m *communication.Message) (*communication.Message, error) {

	msg,_ := cryptoWrapper.DecryptAsymetric(m.Text,s.privateKey)
	log.Printf(string(msg))

	rmessage, _ := cryptoWrapper.EncryptAsymmetric(msg,s.publicKeys[m.Id])

	return &communication.Message{Text: rmessage},nil
}

func (s *GRPCServer) Listen() {
	lis, err := net.Listen("tcp", s.port)
	if err != nil {
		fmt.Errorf("cannot listen to port %v", err)
	}
	grpcServer := grpc.NewServer()
	communication.RegisterCommunicationServer(grpcServer, &GRPCServer{
		port:                             s.port,
		tlsPrivKey:                       s.tlsPrivKey,
		tlsPublicKey:                     s.tlsPublicKey,
		privateKey:                       s.privateKey,
		publicKey:                        s.publicKey,
		keyExchange:                      s.keyExchange,
		exchangeObjects:                  s.exchangeObjects,
		publicKeys:                       s.publicKeys,
		UnimplementedCommunicationServer: communication.UnimplementedCommunicationServer{},
	})

	go func() {
		log.Printf("server listening at %v", lis.Addr())

		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()
}
