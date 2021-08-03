package main

import (
	client "DHE/Client"
	grpcnode "DHE/grpc"
	communication "DHE/grpc/pb"
	"context"
	"log"
)

type server struct {
	communication.UnimplementedGreeterServer
}

// SayHello implements helloworld.GreeterServer
func (s *server) SayHello(ctx context.Context, in *communication.HelloRequest) (*communication.HelloReply, error) {
	log.Printf("Received: %v", in.GetName())
	return &communication.HelloReply{Message: "Hello " + in.GetName()}, nil
}

func main() {
	c1, _ := client.New("Address1")
	c2, _ := client.New("Address2")



	c1.Register(c2)



c:= grpcnode.New(":50052",":50051")
d:= grpcnode.New(":50051",":50052")
c.Serve()
d.Serve()
c.SayHello("Test from 1")
d.SayHello("Test from 2")


}
