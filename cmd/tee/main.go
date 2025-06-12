package main

import (
	"tee-node/pkg/tee/attestation"
	"tee-node/pkg/tee/processor"
	"tee-node/pkg/tee/settings"

	"tee-node/pkg/tee/node"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
)

func main() {
	err := node.InitNode()
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
	processor.RunTeeProcessor(settings.ProxyUrl)
}
