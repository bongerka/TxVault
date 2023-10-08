package client

import (
	"github.com/hashicorp/vault/api"
)

type Client interface {
	GetSecret(secretPath string) (string, bool, error)
}

type clientConnection struct {
	client *api.Client
}

func newClientConnection(client *api.Client) Client {
	return &clientConnection{client}
}
