package testutils

import (
	"testing"

	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/wallets"
	"github.com/stretchr/testify/require"
)

// Setup provisions a test node and fresh storages for integration-style tests.
func Setup(t *testing.T) (*node.Node, *policy.Storage, *wallets.Storage) {
	t.Helper()

	node, err := node.Initialize(node.ZeroState{})
	require.NoError(t, err)

	ps := policy.InitializeStorage()
	ws := wallets.InitializeStorage()

	return node, ps, ws
}
