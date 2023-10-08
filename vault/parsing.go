package vault

import (
	"TxVault/config"
	"TxVault/vault/client"
	"encoding/json"
	"fmt"
	"github.com/rogpeppe/go-internal/modfile"
	"github.com/spf13/viper"
	"log"
	"os"
	"reflect"
	"sync"
)

type parser struct {
	client   client.Client
	vaultCfg *config.YmlConfig
}

func newParser(vaultCfg *config.YmlConfig) *parser {
	clientConn, err := client.NewClientConnection(vaultCfg.Vault.Addr, vaultCfg.Vault.RoleId, vaultCfg.Vault.SecretId)
	if err != nil {
		log.Fatal("Unable to connect client to Vault: ", err)
	}

	return &parser{clientConn, vaultCfg}
}

func GetConfig(configPath string, cfg any) {
	vaultCfg := parseApproleConfig(configPath)
	p := newParser(vaultCfg)
	mapConfig := p.getMapConfig(cfg)

	data, err := convertToJSON(mapConfig)
	if err != nil {
		log.Fatalln("Unable to unmarshal config data: ", err)
	}

	err = json.Unmarshal(data, &cfg)
	if err != nil {
		log.Fatalln("Unable to unmarshal config data: ", err)
	}
}

func (parser *parser) getMapConfig(config any) map[string]any {
	mapConfig := make(map[string]any)
	parser.getVaultPathsRecursively(config, "", mapConfig)
	return mapConfig
}

func (parser *parser) getVaultPathsRecursively(config any, prefix string, secretPaths map[string]any) {
	value := reflect.ValueOf(config).Elem()
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}

	if value.Kind() == reflect.Struct {
		typ := value.Type()
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			tag := field.Tag.Get("vault")
			curPath := tag

			switch tag {
			case "UserName":
				curPath = fmt.Sprintf("Users/%s", parser.vaultCfg.Vault.RoleId)
			case "TxName":
				name := GetServiceName()
				curPath = fmt.Sprintf("Services/%s", name)
			}

			path := prefix + curPath
			fieldValue := value.Field(i)
			if fieldValue.Kind() == reflect.Struct {
				subSecrets := make(map[string]any)
				parser.getVaultPathsRecursively(fieldValue.Addr().Interface(), path+"/", subSecrets)
				secretPaths[tag] = subSecrets
			} else {
				val, ok, err := parser.getSecret(path)
				if !ok {
					secretPaths[tag] = nil
				}
				if err != nil || !ok {
					continue
				}
				secretPaths[tag] = val
			}
		}
	}
}

func (parser *parser) getSecret(secretPath string) (string, bool, error) {
	value, ok, err := parser.client.GetSecret(secretPath)
	if err != nil {
		return "", false, fmt.Errorf("unable to work with secrets: %v", err)
	}
	if ok {
		return value, true, nil
	}

	return "", false, fmt.Errorf("permission deny or secret is not existing. Secret: %s", secretPath)
}

func convertToJSON(data map[string]any) ([]byte, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

var serviceName string
var once sync.Once

func GetServiceName() string {
	once.Do(func() {
		goModPath := "go.mod"

		content, err := os.ReadFile(goModPath)
		if err != nil {
			log.Fatalln("Unable to read go.mod: ", err)
		}

		modFile, err := modfile.Parse("go.mod", content, nil)
		if err != nil {
			log.Fatalln("Unable to parse go.mod: ", err)
		}

		serviceName = modFile.Module.Mod.Path
	})

	return serviceName
}

func parseApproleConfig(configPath string) *config.YmlConfig {
	var cfg config.YmlConfig

	viper.SetConfigFile(configPath)

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalln("Unable to read Vault config: ", err)
	}

	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatalln("Unable to unmarshal Vault config: ", err)
	}

	return &cfg
}
