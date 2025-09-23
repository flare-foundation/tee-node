package server

import (
	exampleextension "github.com/flare-foundation/tee-node/internal/extension/example_extension"
	"github.com/flare-foundation/tee-node/internal/extension/server"
	"github.com/flare-foundation/tee-node/internal/router"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/wallets"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
)

// Starts PMW tee node.
//
// setProxyPort is the port that exposes endpoint for setting proxy's url.
func StartServerPMW(setProxyPort int) {
	logger.Set(logger.Config{Console: true, Level: settings.LogLevel})

	teeNode, err := node.Initialize(node.ZeroState{})
	if err != nil {
		logger.Fatalf("failed to initialize: %v", err)
	}

	ws := wallets.InitializeStorage()
	ps := policy.InitializeStorage()

	pc := settings.NewProxyConfigServer(setProxyPort)
	go pc.Serve() //nolint:errcheck

	r := router.NewPMWRouter(teeNode, ws, ps, pc.ProxyUrl)

	r.Run(teeNode)
}

// Starts tee node for extensions.
//
// setProxyPort is the port that exposes endpoint for setting proxy's url.
// serverPort is the port that exposes endpoints for extension interaction.
// extensionPort is the port where where extension exposes /action endpoint.
func StartServerExtension(setProxyPort, serverPort, extensionPort int) {
	logger.Set(logger.Config{Console: true, Level: settings.LogLevel})

	teeNode, err := node.Initialize(node.ZeroState{})
	if err != nil {
		logger.Fatalf("failed to initialize: %v", err)
	}

	ws := wallets.InitializeStorage()
	ps := policy.InitializeStorage()

	pc := settings.NewProxyConfigServer(setProxyPort)
	go pc.Serve() //nolint:errcheck

	extServer := server.NewExtensionServer(serverPort, teeNode, ws, pc.ProxyUrl)

	go extServer.Serve() //nolint:errcheck

	r := router.NewExtensionRouter(teeNode, ws, ps, extensionPort, pc.ProxyUrl)

	// Launch the json rpc server
	r.Run(teeNode)
}

// Starts the example extension.
//
// serverPort is the port where tee node severs endpoints for interaction.
// extensionPort is the port where where extension exposes /action endpoint.
func StartExampleExtension(serverPort, extensionPort int) {
	server := exampleextension.NewDummyExtensionServer(extensionPort, serverPort)

	server.Serve() //nolint:errcheck
}
