package grpcnode

import (
	communication "DHE/grpc/pb"
	"context"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	"log"
	"net"
)



type server struct {
	port string
	communication.UnimplementedGreeterServer
}

func NewServer(port string) *server {
	server:=server{port: port}
	return &server
}

func (s *server) SayHello(ctx context.Context, in *communication.HelloRequest) (*communication.HelloReply, error) {
	p, _ := peer.FromContext(ctx)

	log.Printf("Received: %v from %v", in.GetName(),p.Addr.String())
	return &communication.HelloReply{Message: "Hello " + in.GetName()}, nil
}

func (s *server) Listen()  {
	lis, err := net.Listen("tcp", s.port)
	if err != nil {
		fmt.Errorf("cannot listen to port %v",err)
	}
	grpcServer := grpc.NewServer()
	communication.RegisterGreeterServer(grpcServer,&server{})

	go func() {
		log.Printf("server listening at %v", lis.Addr())

		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()
}





