package server

import (
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

// StartServerPMW boots the PMW TEE node and exposes the proxy configuration
// endpoint on the provided port.
func StartServerPMW(setProxyPort int) {
	logger.Set(logger.Config{Console: true, Level: settings.LogLevel})

	teeNode, err := node.Initialize(node.ZeroState{})
	if err != nil {
		logger.Fatalf("failed to initialize: %v", err)
	}

	ws := wallets.InitializeStorage()
	ps := policy.InitializeStorage()

	pc := settings.NewConfigServer(setProxyPort, teeNode)
	go pc.Serve() //nolint:errcheck

	r := router.NewPMWRouter(teeNode, ws, ps, pc.ProxyURL)

	r.Run(teeNode)
}

// StartServerExtension runs the extension-enabled TEE node and supporting
// HTTP servers.
func StartServerExtension(setProxyPort, serverPort, extensionPort int) {
	logger.Set(logger.Config{Console: true, Level: settings.LogLevel})

	teeNode, err := node.Initialize(node.ZeroState{})
	if err != nil {
		logger.Fatalf("failed to initialize: %v", err)
	}

	ws := wallets.InitializeStorage()
	ps := policy.InitializeStorage()

	pc := settings.NewConfigServer(setProxyPort, teeNode)
	go pc.Serve() //nolint:errcheck

	extServer := server.NewExtensionServer(serverPort, teeNode, ws, pc.ProxyURL)

	go extServer.Serve() //nolint:errcheck

	r := router.NewExtensionRouter(teeNode, ws, ps, extensionPort, pc.ProxyURL)

	// Launch the json rpc server
	r.Run(teeNode)
}

func StartTestServerExtension(t *testing.T, setProxyPort, serverPort, extensionPort int) (common.Address, *wallets.Storage) {
	logger.Set(logger.Config{Console: true, Level: settings.LogLevel})

	teeNode, err := node.Initialize(node.ZeroState{})
	if err != nil {
		t.Fatalf("failed to initialize: %v", err)
	}

	ws := wallets.InitializeStorage()
	ps := policy.InitializeStorage()

	pc := settings.NewProxyConfigServer(setProxyPort)
	go pc.Serve() //nolint:errcheck

	extServer := server.NewExtensionServer(serverPort, teeNode, ws, pc.ProxyUrl)

	go extServer.Serve() //nolint:errcheck

	r := router.NewExtensionRouter(teeNode, ws, ps, extensionPort, pc.ProxyUrl)

	// Launch the json rpc server
	go r.Run(teeNode)

	return teeNode.TeeID(), ws
}

// StartExampleExtension launches the dummy extension server on the configured
// ports.
func StartExampleExtension(serverPort, extensionPort int) {
	server := exampleextension.NewDummyExtensionServer(extensionPort, serverPort)

	server.Serve() //nolint:errcheck,gosec
}
