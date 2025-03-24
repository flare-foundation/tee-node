package main

import (
	"log"
	"tee-node/pkg/attestation"
	"tee-node/pkg/config"

	"tee-node/pkg/node"
	"tee-node/pkg/service"

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

	err = attestation.SetGoogleCert()
	if err != nil {
		logger.Fatalf("failed to load certificate: %v", err)
	}
	err = attestation.SelfAttest()
	if err != nil {
		logger.Fatalf("self attestation failed: %v", err)
	}

	// Launch the json rpc server
	go service.LaunchServer(config.Server.Port)
	// Launch the websocket server
	service.LaunchWSServer(config.Server.WSPort)
}
