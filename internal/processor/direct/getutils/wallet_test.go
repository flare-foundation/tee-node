package getutils

import (
	"crypto/ecdsa"
	"encoding/json"
	"testing"

	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestGetWalletPackage(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test
	err := node.InitNode(types.State{})
	require.NoError(t, err)
	myTeeId := node.GetTeeId()

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys, err := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)
	require.NoError(t, err)

	mockWalletId1 := common.HexToHash("0xabcdef")
	mockKeyId1 := uint64(1)
	walletProofs := make(map[common.Hash]wallet.ITeeWalletKeyManagerKeyExistence)

	walletProofs[mockWalletId1] = testutils.CreateMockWallet(t, myTeeId, mockWalletId1, mockKeyId1, epochId, []*ecdsa.PrivateKey{privKeys[0]}, nil)

	mockWalletId2 := common.HexToHash("0xabcdefab")
	mockKeyId2 := uint64(2)

	walletProofs[mockWalletId2] = testutils.CreateMockWallet(t, myTeeId, mockWalletId2, mockKeyId2, epochId, []*ecdsa.PrivateKey{privKeys[1]}, nil)

	walletsPackage, err := GetKeyInfoPackage()
	require.NoError(t, err)

	var existenceProofs []types.WalletSignedKeyExistenceProof
	err = json.Unmarshal(walletsPackage, &existenceProofs)
	require.NoError(t, err)

	require.Len(t, existenceProofs, 2)

	for _, proof := range existenceProofs {
		err = utils.VerifySignature(crypto.Keccak256(proof.KeyExistenceProof), proof.Signature, myTeeId)
		require.NoError(t, err)

		walletExistenceProof, err := structs.Decode[wallet.ITeeWalletKeyManagerKeyExistence](wallet.KeyExistenceStructArg, proof.KeyExistenceProof)
		require.NoError(t, err)

		require.Equal(t, walletProofs[walletExistenceProof.WalletId], walletExistenceProof)
	}
}
