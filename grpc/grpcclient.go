package grpcnode

import (
	communication "DHE/grpc/pb"
	"context"
	"google.golang.org/grpc"
	"log"
	"time"
)

type client struct {
	address string
}

func (c *client) Greet(msg string) {
	conn, err := grpc.Dial(c.address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	client := communication.NewGreeterClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := client.SayHello(ctx, &communication.HelloRequest{Name: msg})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("Greeting: %s", r.GetMessage())
}

func NewClient(address string) *client {
	c := client{address: address}
	return &c
}
