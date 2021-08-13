package main

import (
	client "DHE/Client"
)

func main() {

	c1, _ := client.New(0,":50052", []string{":50051"})
	c2, _ := client.New(1,":50051", []string{":50052"})

	c1.Register(c2)
	c1.SendMessage(":50051")
	//d:= grpcnode.New(":50051",":50052")
	//e:= grpcnode
	//.New(":50052",":50053")

	//d.Serve()
	//e.Serve()
	////c.SayHello("Test from 1")
	//e.SayHello("Test from 3")
	//d.SayHello("Test from 2")

}
