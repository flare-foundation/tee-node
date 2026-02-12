package main

import (
	"github.com/flare-foundation/tee-node/internal/router"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/node"

	"github.com/flare-foundation/go-flare-common/pkg/logger"

	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/wallets"
)

func main() {
	logger.Set(logger.Config{Console: true, Level: settings.LogLevel})

	teeNode, err := node.Initialize(node.ZeroState{})
	if err != nil {
		logger.Fatalf("failed to initialize: %v", err)
	}
	ws := wallets.InitializeStorage()
	ps := policy.InitializeStorage()
	logger.Info("tee node initialized")

	pc := settings.NewConfigServer(settings.ConfigPort, teeNode)
	go func() {
		err := pc.Serve()
		if err != nil {
			logger.Errorf("config server: %w", err)
		}
	}()

	r := router.NewPMWRouter(teeNode, ws, ps, pc.ProxyURL)

	// Launch the json rpc server
	r.Run(teeNode)
}
