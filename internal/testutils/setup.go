package testutils

import (
	"testing"

	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/internal/wallets"
	"github.com/stretchr/testify/require"
)

// DefaultTestChainID is set by Setup unless WithoutChainID is passed.
const DefaultTestChainID uint64 = 31337

type setupConfig struct {
	skipChainID bool
}

// SetupOption customizes the node provisioned by Setup.
type SetupOption func(*setupConfig)

// WithoutChainID provisions the node without a chain ID, so ChainID() errors.
func WithoutChainID() SetupOption {
	return func(c *setupConfig) { c.skipChainID = true }
}

// Setup provisions a test node and fresh storages for integration-style tests.
func Setup(t *testing.T, opts ...SetupOption) (*node.Node, *policy.Storage, *wallets.Storage) {
	t.Helper()

	var cfg setupConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	n, err := node.Initialize(node.ZeroState{})
	require.NoError(t, err)

	if !cfg.skipChainID {
		// A chain ID is required to sign machine data for registration.
		require.NoError(t, n.SetChainID(DefaultTestChainID))
	}

	ps := policy.InitializeStorage()
	ws := wallets.InitializeStorage()

	return n, ps, ws
}
