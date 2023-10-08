package root

import (
	"github.com/hashicorp/vault/api"
)

type Root interface {
	CreateUserWithAppRole(username, roleName string)
	CreateNewRole(roleName string, policieNames []string)
	ReadRoleID(roleName string) string
	ReadSecretID(roleName string) string
}

type rootConnection struct {
	client *api.Client
}

func newRootConnection(client *api.Client) Root {
	return &rootConnection{client}
}
