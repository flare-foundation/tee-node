package config

import (
	"fmt"
	"os"

	"github.com/naoina/toml"
	"gorm.io/gorm/logger"
)

type NodeConfig struct {
	Logging logger.Config `toml:"logger"`
	Server  Server        `toml:"server"`
}

type Server struct {
	Port   int `toml:"port"`
	WSPort int `toml:"ws_port"`
}

// ReadConfigs reads user and system configurations from userFilePath and systemDirectoryPath.
//
// System configurations are read for Chain and protocolID set in the user configurations.
func ReadConfig(filePath string) (*NodeConfig, error) {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed reading file %s with: %s", filePath, err)
	}

	config := NodeConfig{}
	err = toml.Unmarshal(file, &config)
	if err != nil {
		return nil, fmt.Errorf("failed unmarshaling file %s with: %s", filePath, err)
	}

	return &config, nil
}
