package root

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"log"
)

func NewRootConnection(addr, token string) Root {
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		log.Println("Unable to create client: ", err)
	}

	_ = client.SetAddress(addr)
	client.SetToken(token)
	return newRootConnection(client)
}

func (root *rootConnection) CreateNewRole(roleName string, policiesNames []string) {
	roleConfig := map[string]interface{}{
		"policies": policiesNames,
	}

	_, err := root.client.Logical().Write("auth/approle/role/"+roleName, roleConfig)
	if err != nil {
		log.Println("Unable to create new role: ", err)
	}

	fmt.Printf("Role %s successfully created with policise: %s\n", roleName, policiesNames)
}

func (root *rootConnection) ReadRoleID(roleName string) string {
	secret, err := root.client.Logical().Read(fmt.Sprintf("auth/approle/role/%s/role-id", roleName))
	if err != nil {
		log.Printf("Unable to read role-id: %v", err)
	}

	if secret == nil || secret.Data == nil {
		log.Println("Empty response")
	}

	return secret.Data["role_id"].(string)
}

func (root *rootConnection) CreateUserWithAppRole(username, roleName string) {
	userConfig := map[string]interface{}{
		"policies":        roleName,
		"bound_cidr_list": "",
		"max_ttl":         "0s",
	}

	_, err := root.client.Logical().Write("auth/approle/map/user-id/"+username, userConfig)
	if err != nil {
		log.Println("Unable to create client: ", err)
	}

	fmt.Printf("User %s successfully created with role %s\n", username, roleName)
}

func (root *rootConnection) ReadSecretID(roleName string) string {
	secretIdResponse, err := root.client.Logical().Write("auth/approle/role/"+roleName+"/secret-id", nil)
	if err != nil || secretIdResponse == nil || secretIdResponse.Data == nil {
		log.Println("Unable to create secret-id: ", err)
		return ""
	}

	if secretIdResponse == nil || secretIdResponse.Data == nil {
		log.Println("Empty response")
	}

	secretId := secretIdResponse.Data["secret_id"].(string)
	fmt.Println("secret-id successfully created: ", secretId)

	return secretId
}
