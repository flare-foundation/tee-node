package config

import (
	"fmt"
	"os"

	"github.com/flare-foundation/go-flare-common/pkg/database"
	"github.com/naoina/toml"
	"gorm.io/gorm/logger"
)

type ClientConfig struct {
	DB      database.Config `toml:"db"`
	Logging logger.Config   `toml:"logger"`
	Chain   Chain           `toml:"chain"`
	Server  Server          `toml:"server"`
}

type Server struct {
	Host             string   `toml:"host"`
	Backups          []string `toml:"backups"`
	PubKeys          []string `toml:"pub_keys"`
	PubKey           string   `toml:"pub_key"`
	BackupsThreshold int      `toml:"backups_threshold"`
}

type Chain struct {
	RelayContractAddress              string `toml:"relay_contract_address"`
	FlareSystemManagerContractAddress string `toml:"flare_system_manager_contract_address"`
}

// ReadConfigs reads user and system configurations from userFilePath and systemDirectoryPath.
//
// System configurations are read for Chain and protocolID set in the user configurations.
func ReadConfig(filePath string) (*ClientConfig, error) {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed reading file %s with: %s", filePath, err)
	}

	config := ClientConfig{}
	err = toml.Unmarshal(file, &config)
	if err != nil {
		return nil, fmt.Errorf("failed unmarshaling file %s with: %s", filePath, err)
	}

	return &config, nil
}
