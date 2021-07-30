package main

import (
	mock_Client "DHE/test/mock"
	"github.com/golang/mock/gomock"
	"testing"
)

func TestName(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient1 := mock_NewMockNetworkElement(ctrl)
	mockClient2 := mock_NewMockNetworkElement(ctrl)

	mockClient1.EXPECT().Register(mockClient2).MaxTimes(1)
}
