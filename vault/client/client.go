package client

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
	"log"
	"strings"
)

func NewClientConnection(addr, roleID, secretID string) (Client, error) {
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		log.Printf("unable to create client: %v\n", err)
	}

	_ = client.SetAddress(addr)

	if roleID == "" {
		return nil, fmt.Errorf("no role ID was provided in APPROLE_ROLE_ID env var")
	}

	secretId := &auth.SecretID{FromString: secretID}

	appRoleAuth, err := auth.NewAppRoleAuth(
		roleID,
		secretId,
		//auth.WithWrappingToken(), // Only required if the secret ID is response-wrapped.
	)

	if err != nil {
		return nil, fmt.Errorf("unable to initialize AppRole auth method: %w", err)
	}

	authInfo, err := client.Auth().Login(context.Background(), appRoleAuth)

	if err != nil {
		return nil, fmt.Errorf("unable to login to AppRole auth method: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("no auth info was returned after login: %w", err)
	}

	return newClientConnection(client), nil
}

func (approle *clientConnection) GetSecret(secretPath string) (string, bool, error) {
	secret, err := approle.client.KVv2("secret").Get(context.Background(), secretPath)

	if err != nil || secret == nil || secret.Data == nil {
		if strings.Contains(err.Error(), "permission denied") ||
			strings.Contains(err.Error(), "secret not found") {
			return "", false, nil
		}
		return "", false, err
	}

	data, ok := secret.Data["key"].(string)
	if !ok {
		return "", false, nil
	}

	return data, true, nil
}
