package client

import (
	"bytes"
	"crypto/rsa"
	"github.com/golang/mock/gomock"
	"log"
	"testing"
)

func TestClient_GetAddress(t *testing.T) {
	c1, _ := New("CustomAddress")
	c2, _ := New("NewAddress")
	c1.Register(c2)
	c2Added := ""
	c1Added := ""
	for value := range c1.publicKeys {
		if value.GetAddress() == c2.GetAddress() {
			c2Added = value.GetAddress()
		}
	}
	for value := range c2.publicKeys {
		if value.GetAddress() == c1.GetAddress() {
			c1Added = value.GetAddress()
		}
	}
	if c1.GetAddress() != c1Added || c2.GetAddress() != c2Added {
		t.Errorf("registration of node not has failed ")
	}
}

func TestClient_ExchangeSecret(t *testing.T) {
	c2, _ := New("myAddress")
	c1, _ := New("CustomAddress")
	c1.Register(c2)
	keyElement1 := c1.exchangeObjects[c2]
	keyElement2 := c2.exchangeObjects[c1]
	if bytes.Equal(keyElement2.secret, keyElement1.secret) == false {
		t.Errorf("Secrets do not match")
	}
	log.Println("Secrets Match")
}
func TestClient_ExchangePublicKeys(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	c2, _ := New("myAddress")
	c1, _ := New("CustomAddress")
	c1.Register(c2)
	keyElement1 := c1.publicKeys[c2]
	keyElement2 := c2.publicKeys[c1]

	if keycompare(keyElement2, c1.publicKey) == false || keycompare(keyElement1, c2.publicKey) == false {
		t.Errorf("Exchanged public Keys do not match")
	}
}

func TestSendMessage(t *testing.T) {

	testMessage := []byte("Das Leben ist eine Freude. Für Manche")
	c1, _ := New("Address 1")
	c2, _ := New("Address 2")

	c1.Register(c2)

	c1.Send(testMessage, c2)

	if c2.receivedMessages[0] != string(testMessage) {
		t.Errorf("An error occured in sending. Send and receive do not match")
	}
	if c1.sentMessages[0] != string(testMessage) {
		t.Errorf("sendMessages receives wrong data")
	}
}

func TestRegister(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	m := NewMockNetworkElement(ctrl)

	c1, _ := New("Address 1")

	m.EXPECT().keyExchangeI(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	m.EXPECT().GetAddress().Times(1)
	c1.Register(m)
}

func TestDoubleRegistering(t *testing.T) {
	c2, _ := New("Address 1")
	c1, _ := New("Address 2")

	for i := 0; i < 100; i++ {
		c1.Register(c2)
	}

	if len(c1.publicKeys) < 1 {
		t.Errorf("double created registering")
	} else if len(c1.publicKeys) == 0 {
		t.Errorf("not registered")
	}
}

func keycompare(a, b rsa.PublicKey) bool {
	if a.E != b.E {
		return false
	}
	return a.N.Cmp(b.N) == 0
}
