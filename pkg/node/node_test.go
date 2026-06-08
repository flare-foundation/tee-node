package node

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/machinepath"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/stretchr/testify/require"
)

func TestMachinePathsZeroValue(t *testing.T) {
	n, err := Initialize(ZeroState{})
	require.NoError(t, err)

	paths, nonce := n.MachinePaths()
	require.Empty(t, paths)
	require.Equal(t, uint64(0), nonce)
}

func TestSetMachinePathListMonotonicNonce(t *testing.T) {
	n, err := Initialize(ZeroState{})
	require.NoError(t, err)

	pathsA := []machinepath.IMachinePathManagerMachinePath{{
		SourceTeeIds:      []common.Address{common.HexToAddress("0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1")},
		DestinationTeeIds: []common.Address{common.HexToAddress("0x1111111111111111111111111111111111111111")},
	}}
	require.NoError(t, n.SetMachinePathList(pathsA, 1))

	gotPaths, gotNonce := n.MachinePaths()
	require.Equal(t, pathsA, gotPaths)
	require.Equal(t, uint64(1), gotNonce)

	pathsB := []machinepath.IMachinePathManagerMachinePath{{
		SourceTeeIds:      []common.Address{common.HexToAddress("0xb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2")},
		DestinationTeeIds: []common.Address{common.HexToAddress("0x2222222222222222222222222222222222222222")},
	}}

	// Same and lower nonces are rejected and state is preserved.
	for _, badNonce := range []uint64{1, 0} {
		require.Error(t, n.SetMachinePathList(pathsB, badNonce))
		gotPaths, gotNonce = n.MachinePaths()
		require.Equal(t, pathsA, gotPaths)
		require.Equal(t, uint64(1), gotNonce)
	}

	// Strictly higher nonce is accepted; the path list is replaced.
	require.NoError(t, n.SetMachinePathList(pathsB, 2))
	gotPaths, gotNonce = n.MachinePaths()
	require.Equal(t, pathsB, gotPaths)
	require.Equal(t, uint64(2), gotNonce)
}

func TestMachinePathsDefensiveCopy(t *testing.T) {
	n, err := Initialize(ZeroState{})
	require.NoError(t, err)

	srcAddr := common.HexToAddress("0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1")
	dstAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	paths := []machinepath.IMachinePathManagerMachinePath{{
		SourceTeeIds:      []common.Address{srcAddr},
		DestinationTeeIds: []common.Address{dstAddr},
	}}
	require.NoError(t, n.SetMachinePathList(paths, 1))

	// Mutating the caller's slices after the call must not affect stored state.
	paths[0].SourceTeeIds[0] = common.HexToAddress("0x9999999999999999999999999999999999999999")
	paths[0].DestinationTeeIds[0] = common.HexToAddress("0x9999999999999999999999999999999999999999")

	got, _ := n.MachinePaths()
	require.Equal(t, srcAddr, got[0].SourceTeeIds[0])
	require.Equal(t, dstAddr, got[0].DestinationTeeIds[0])

	// Mutating the returned slices must not affect the next read.
	got[0].SourceTeeIds[0] = common.HexToAddress("0x8888888888888888888888888888888888888888")
	got[0].DestinationTeeIds[0] = common.HexToAddress("0x8888888888888888888888888888888888888888")
	got2, _ := n.MachinePaths()
	require.Equal(t, srcAddr, got2[0].SourceTeeIds[0])
	require.Equal(t, dstAddr, got2[0].DestinationTeeIds[0])
}

func TestSetChainID(t *testing.T) {
	t.Run("set then read", func(t *testing.T) {
		n, err := Initialize(ZeroState{})
		require.NoError(t, err)

		_, err = n.ChainID()
		require.Error(t, err) // unset

		require.NoError(t, n.SetChainID(42))
		cid, err := n.ChainID()
		require.NoError(t, err)
		require.Equal(t, uint64(42), cid)
	})

	t.Run("zero is rejected", func(t *testing.T) {
		n, err := Initialize(ZeroState{})
		require.NoError(t, err)
		require.EqualError(t, n.SetChainID(0), "0 is invalid chainID")
	})

	t.Run("cannot be set twice", func(t *testing.T) {
		n, err := Initialize(ZeroState{})
		require.NoError(t, err)

		require.NoError(t, n.SetChainID(42))
		require.EqualError(t, n.SetChainID(43), "chainID already set")

		cid, err := n.ChainID()
		require.NoError(t, err)
		require.Equal(t, uint64(42), cid) // unchanged
	})
}

func TestChainIDFromEnv(t *testing.T) {
	t.Run("valid value is loaded", func(t *testing.T) {
		t.Setenv(settings.ChainIDEnvVar, "42")
		n, err := Initialize(ZeroState{})
		require.NoError(t, err)
		cid, err := n.ChainID()
		require.NoError(t, err)
		require.Equal(t, uint64(42), cid)
	})

	t.Run("zero is rejected", func(t *testing.T) {
		t.Setenv(settings.ChainIDEnvVar, "0")
		_, err := Initialize(ZeroState{})
		require.Error(t, err)
	})

	t.Run("non-numeric is rejected", func(t *testing.T) {
		t.Setenv(settings.ChainIDEnvVar, "not-a-number")
		_, err := Initialize(ZeroState{})
		require.Error(t, err)
	})
}
