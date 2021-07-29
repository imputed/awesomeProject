package main

import (
	"DHE/Client"
)
func main()  {
c1 := client.New("Address1")
c2 := client.New("Address2")

c1.Register(c2)
_= c1.Broadcast()

 c1.InitKeyExchange(c2)



}
