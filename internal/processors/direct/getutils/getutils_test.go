package getutils

import (
	"crypto/ecdsa"
	"encoding/json"
	"testing"

	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/utils"
	pwallets "github.com/flare-foundation/tee-node/pkg/wallets"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestKeyInfo(t *testing.T) {
	testNode, pStorage, wStorage := testutils.Setup(t)

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys, err := testutils.GenerateAndSetInitialPolicy(pStorage, numVoters, randSeed, epochId)
	require.NoError(t, err)

	mockWalletID1 := common.HexToHash("0xabcdef")
	mockKeyID1 := uint64(1)
	walletProofs := make(map[common.Hash]wallet.ITeeWalletKeyManagerKeyExistence)

	walletProofs[mockWalletID1] = testutils.CreateMockWallet(t, testNode, pStorage, wStorage, mockWalletID1, mockKeyID1, epochId, []*ecdsa.PrivateKey{privKeys[0]}, nil)

	mockWalletID2 := common.HexToHash("0xabcdefab")
	mockKeyID2 := uint64(2)

	walletProofs[mockWalletID2] = testutils.CreateMockWallet(t, testNode, pStorage, wStorage, mockWalletID2, mockKeyID2, epochId, []*ecdsa.PrivateKey{privKeys[1]}, nil)

	proc := Processor{
		InformerAndSigner: testNode,
		pStorage:          pStorage,
		wStorage:          wStorage,
	}

	walletsPackage, err := proc.KeysInfo(nil)
	require.NoError(t, err)

	var existenceProofs []pwallets.SignedKeyExistenceProof
	err = json.Unmarshal(walletsPackage, &existenceProofs)
	require.NoError(t, err)

	require.Len(t, existenceProofs, 2)

	for _, proof := range existenceProofs {
		err = utils.VerifySignature(crypto.Keccak256(proof.KeyExistence), proof.Signature, testNode.TeeID())
		require.NoError(t, err)

		walletExistenceProof, err := structs.Decode[wallet.ITeeWalletKeyManagerKeyExistence](wallet.KeyExistenceStructArg, proof.KeyExistence)
		require.NoError(t, err)

		require.Equal(t, walletProofs[walletExistenceProof.WalletId], walletExistenceProof)
	}
}
