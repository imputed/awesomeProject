package client

import (
	"bytes"
	"crypto/rsa"
	"github.com/golang/mock/gomock"
	"testing"
)

func TestClient_GetAddress(t *testing.T) {
	c1 := New("CustomAddress")
	c2 := New("NewAddress")
	c1.Register(c2)
	c2Added := c1.neighbours[0]

	if (c2.GetAddress() != c2Added.GetAddress()) || len(c1.neighbours) != 1 {
		t.Errorf("registration of node not has failed ")
	}
}

func TestClient_ExchangeSecret(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	c2 := New("myAddress")
	c1 := New("CustomAddress")
	c1.Register(c2)
	err := c1.InitKeyExchange(c2)
	if err != nil {
		return
	}
	keyElement1 := c1.exchangeObjects[c2]
	keyElement2 := c2.exchangeObjects[c1]
	if bytes.Equal(keyElement2.secret, keyElement1.secret) == false {
		t.Errorf("Secrets do not match")
	}
}
func TestClient_ExchangePublicKeys(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	c2 := New("myAddress")
	c1 := New("CustomAddress")
	c1.Register(c2)
	err := c1.InitKeyExchange(c2)
	if err != nil {
		return
	}
	keyElement1 := c1.publicKeys[c2]
	keyElement2 := c2.publicKeys[c1]

	if keycompare(keyElement2, c1.publicKey) == false || keycompare(keyElement1,c2.publicKey) == false{
		t.Errorf("Exchanged public Keys do not match")
	}
}

func keycompare(a, b rsa.PublicKey) bool {
	if a.E != b.E {
		return false
	}
	return a.N.Cmp(b.N) == 0
}
