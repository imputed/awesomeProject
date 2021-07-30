package main

import (
	client "DHE/Client"
)

func main() {
	c1, _ := New("Address1")
	c2, _ := New("Address2")

	c1.Register(c2)

}
