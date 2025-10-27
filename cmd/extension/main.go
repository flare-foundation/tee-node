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

	pc := settings.NewConfigServer(settings.ProxyConfigureServerPort, teeNode)
	go pc.Serve() //nolint:errcheck

	extServer := server.NewExtensionServer(settings.ExtensionServerPort, teeNode, ws, pc.ProxyURL)

	go extServer.Serve() //nolint:errcheck

	r := router.NewExtensionRouter(teeNode, ws, ps, settings.ExtensionPort, pc.ProxyURL)

	// Launch the json rpc server
	r.Run(teeNode)
}
