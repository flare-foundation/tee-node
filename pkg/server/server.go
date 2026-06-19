package server

import (
	"fmt"

	"github.com/flare-foundation/tee-node/internal/extension/server"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/internal/router"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/internal/testutils"
	walletstorage "github.com/flare-foundation/tee-node/internal/wallets"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
)

// initialize new node, wallet and policy storages, and start a config server.
func initialize(configPort int) (*node.Node, *walletstorage.Storage, *policy.Storage, *settings.ConfigServer, error) {
	// Create a node, storages and a config server.
	teeNode, err := node.Initialize(node.ZeroState{})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to initialize: %w", err)
	}
	ws := walletstorage.InitializeStorage()
	ps := policy.InitializeStorage()
	cs := settings.NewConfigServer(configPort, teeNode)

	// Start the config server.
	go func() {
		err := cs.Serve()
		if err != nil {
			logger.Errorf("config server error: %v", err)
		}
	}()

	return teeNode, ws, ps, cs, nil
}

// StartServerPMW boots the PMW TEE node and exposes the configuration
// endpoint on the provided port.
func StartServerPMW(configPort int) {
	// Initialize.
	teeNode, ws, ps, cs, err := initialize(configPort)
	if err != nil {
		logger.Errorf("node initialization failed: %v", err)
		return
	}

	// Start a PMW router.
	router.NewPMWRouter(teeNode, ws, ps, cs.ProxyURL).Run(teeNode)
}

// StartServerExtension runs the extension-enabled TEE node and supporting
// HTTP servers for testing purposes.
func StartServerExtension(configPort, signPort, extensionPort int) {
	// Initialize.
	teeNode, ws, ps, cs, err := initialize(configPort)
	if err != nil {
		logger.Errorf("node initialization failed: %v", err)
		return
	}

	// Start a signing server.
	go func() {
		err := server.NewSignServer(signPort, teeNode, ws, cs.ProxyURL).Serve()
		if err != nil {
			logger.Errorf("extension server error: %v", err)
		}
	}()

	// Start a forward router.
	router.NewForwardRouter(teeNode, ws, ps, extensionPort, cs.ProxyURL).Run(teeNode)
}

// StartExampleExtension runs a dummy extension signing server for integration
// testing. It mirrors what a real extension exposes without booting a full node.
func StartExampleExtension(signPort, extensionPort int) {
	ext := testutils.NewDummyExtensionServer(extensionPort, signPort)
	ext.Serve() //nolint:errcheck,gosec // example/test helper; serve error is non-fatal here
}
