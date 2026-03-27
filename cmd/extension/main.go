package main

import (
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

	pc := settings.NewConfigServer(settings.ConfigPort, teeNode)
	go func() {
		err := pc.Serve()
		if err != nil {
			logger.Errorf("config server: %w", err)
		}
	}()

	extServer := server.NewSignServer(settings.SignPort, teeNode, ws, pc.ProxyURL)
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
