package vault

type (
	YmlConfig struct {
		Vault VaultConfig `mapstructure:"vault"`
	}

	VaultConfig struct {
		Addr     string `mapstructure:"addr"`
		RoleId   string `mapstructure:"roleId"`
		SecretId string `mapstructure:"secretId"`
	}
)
