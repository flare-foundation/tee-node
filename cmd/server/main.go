package main

import (
	"log"
	"tee-node/internal/config"
	"tee-node/internal/node"
	"tee-node/internal/service"

	"github.com/alexflint/go-arg"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
)

var args struct {
	Config string `default:"config.toml"`
}

func main() {
	arg.MustParse(&args)

	config, err := config.ReadConfig(args.Config)
	if err != nil {
		log.Fatalf("failed to read config: %v", err)
	}

	err = node.InitNode()
	if err != nil {
		logger.Fatalf("failed to initialize: %v", err)
	}

	// Launch the gRPC server
	go service.LaunchServer(config.Server.Port)
	service.LaunchWSServer(config.Server.WSPort)
}
