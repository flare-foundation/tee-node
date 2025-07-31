package main

import (
	"github.com/flare-foundation/tee-node/internal/attestation"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/processor"
	"github.com/flare-foundation/tee-node/internal/settings"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
)

func main() {
	err := node.InitNode(node.ZeroState{})
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

	go settings.ProxyUrlConfigServer()

	// Launch the json rpc server
	processor.RunTeeProcessor()
}
