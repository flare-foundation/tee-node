package main

import (
	"tee-node/internal/node"
	"tee-node/internal/service"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
)

func main() {
	err := node.InitNode()
	if err != nil {
		logger.Fatalf("failed to initialize: %v", err)
	}

	// Launch the gRPC server
	service.LaunchServer(50051) // todo: make configurable port
}
