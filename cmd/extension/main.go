package main

import (
	"github.com/flare-foundation/tee-node/internal/attestation"
	"github.com/flare-foundation/tee-node/internal/extension/server"
	"github.com/flare-foundation/tee-node/internal/router"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/wallets"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
)

func main() {
	if settings.Mode == 1 {
		settings.TestCodeHash = settings.TestCodeHash1 // set different test code hash. Applicable only in mode 1.
	}

	logger.Set(logger.Config{Console: true, Level: settings.LogLevel})

	teeNode, err := node.Initialize(node.ZeroState{})
	if err != nil {
		logger.Fatalf("failed to initialize: %v", err)
	}

	ws := wallets.InitializeStorage()
	ps := policy.InitializeStorage()

	err = attestation.SetGoogleCert()
	if err != nil {
		logger.Fatalf("failed to load certificate: %v", err)
	}

	pc := settings.NewConfigServer(settings.ConfigureServerPort, teeNode)
	go func() {
		err := pc.Serve()
		if err != nil {
			logger.Errorf("config server: %w", err)
		}
	}()

	extServer := server.NewExtenderServer(settings.ExtensionServerPort, teeNode, ws, pc.ProxyURL)
	go func() {
		err := extServer.Serve()
		if err != nil {
			logger.Errorf("extension server: %w", err)
		}
	}()

	r := router.NewForwardRouter(teeNode, ws, ps, settings.ExtensionPort, pc.ProxyURL)

	// Launch the json rpc server
	r.Run(teeNode)
}
