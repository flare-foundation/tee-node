package types_test

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/machinepath"
	"github.com/flare-foundation/tee-node/pkg/types"
)

// TestApproveMachinePathListCalldata guards against signature drift: the
// ABI-derived calldata must equal the selector and arguments of
// approveMachinePathList(uint256,uint256,bytes32).
func TestApproveMachinePathListCalldata(t *testing.T) {
	extensionID := common.HexToHash("0x1234")
	nonce := uint64(7)
	messageHash := common.HexToHash("0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")

	got, err := types.ApproveMachinePathListCalldata(extensionID, nonce, messageHash)
	require.NoError(t, err)

	selector := crypto.Keccak256([]byte("approveMachinePathList(uint256,uint256,bytes32)"))[:4]
	uint256Ty, err := abi.NewType("uint256", "", nil)
	require.NoError(t, err)
	bytes32Ty, err := abi.NewType("bytes32", "", nil)
	require.NoError(t, err)
	enc, err := abi.Arguments{{Type: uint256Ty}, {Type: uint256Ty}, {Type: bytes32Ty}}.Pack(
		new(big.Int).SetBytes(extensionID[:]),
		new(big.Int).SetUint64(nonce),
		[32]byte(messageHash),
	)
	require.NoError(t, err)

	require.Equal(t, append(selector, enc...), got)
}

// TestMachinePathListDataHash guards the encoding: the hash must equal
// keccak256(abi.encode(uint256, uint256, (address[], address[])[])).
func TestMachinePathListDataHash(t *testing.T) {
	extensionID := common.HexToHash("0x1234")
	nonce := uint64(7)
	paths := []machinepath.IMachinePathManagerMachinePath{
		{
			SourceTeeIds:      []common.Address{common.HexToAddress("0x1"), common.HexToAddress("0x2")},
			DestinationTeeIds: []common.Address{common.HexToAddress("0x3")},
		},
		{
			SourceTeeIds:      []common.Address{common.HexToAddress("0x4")},
			DestinationTeeIds: []common.Address{common.HexToAddress("0x5"), common.HexToAddress("0x6")},
		},
	}

	got, err := types.MachinePathListDataHash(extensionID, nonce, paths)
	require.NoError(t, err)

	uint256Ty, err := abi.NewType("uint256", "", nil)
	require.NoError(t, err)
	pathArrayTy, err := abi.NewType("tuple[]", "", []abi.ArgumentMarshaling{
		{Name: "sourceTeeIds", Type: "address[]"},
		{Name: "destinationTeeIds", Type: "address[]"},
	})
	require.NoError(t, err)
	enc, err := abi.Arguments{{Type: uint256Ty}, {Type: uint256Ty}, {Type: pathArrayTy}}.Pack(
		new(big.Int).SetBytes(extensionID[:]),
		new(big.Int).SetUint64(nonce),
		paths,
	)
	require.NoError(t, err)

	require.Equal(t, crypto.Keccak256Hash(enc), got)
}
