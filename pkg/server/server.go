package server

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	exampleextension "github.com/flare-foundation/tee-node/internal/extension/example_extension"
	"github.com/flare-foundation/tee-node/internal/extension/server"
	"github.com/flare-foundation/tee-node/internal/router"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/wallets"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
)

// initialize new node, wallet and policy storages, and start a config server.
func initialize(configPort int) (*node.Node, *wallets.Storage, *policy.Storage, *settings.ConfigServer, error) {
	// Create a node, storages and a config server.
	teeNode, err := node.Initialize(node.ZeroState{})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to initialize: %w", err)
	}
	ws := wallets.InitializeStorage()
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

// StartTestServerExtension runs the extension-enabled TEE node and supporting
// HTTP servers for testing purposes.
//
// configPort is a node's port for receiving configuration requests (like setting proxy URL).
// extenderPort is a node's port for receiving action results from extensions.
// extensionPort is an extension's port that receives actions from its node.
func StartServerExtension(configPort, extenderPort, extensionPort int) {
	// Initialize.
	teeNode, ws, ps, cs, err := initialize(configPort)
	if err != nil {
		logger.Errorf("node initialization failed: %v", err)
		return
	}

	// Start an extender server.
	go func() {
		err := server.NewExtenderServer(extenderPort, teeNode, ws, cs.ProxyURL).Serve()
		if err != nil {
			logger.Errorf("extension server error: %v", err)
		}
	}()

	// Start a forward router.
	router.NewForwardRouter(teeNode, ws, ps, extensionPort, cs.ProxyURL).Run(teeNode)
}

// StartTestServerExtension runs the extension-enabled TEE node and supporting
// HTTP servers for testing purposes.
//
// configPort is a node's port for receiving configuration requests (like setting proxy URL).
// extenderPort is a node's port for receiving action results from extensions.
// extensionPort is an extension's port that receives actions from its node.
func StartTestServerExtension(t *testing.T, configPort, extenderPort, extensionPort int) (common.Address, *wallets.Storage) {
	// Initialize.
	teeNode, ws, ps, cs, err := initialize(configPort)
	if err != nil {
		t.Errorf("node initialization failed: %v", err)
	}

	// Start an extender server.
	go func() {
		err := server.NewExtenderServer(extenderPort, teeNode, ws, cs.ProxyURL).Serve()
		if err != nil {
			t.Errorf("extension server error: %v", err)
		}
	}()

	// Start a forward router.
	go router.NewForwardRouter(teeNode, ws, ps, extensionPort, cs.ProxyURL).Run(teeNode)

	return teeNode.TeeID(), ws
}

// StartExampleExtension launches the dummy extension server on the configured
// ports.
func StartExampleExtension(extenderPort, extensionPort int) {
	server := exampleextension.NewDummyExtensionServer(extensionPort, extenderPort)

	server.Serve() //nolint:errcheck,gosec
}
