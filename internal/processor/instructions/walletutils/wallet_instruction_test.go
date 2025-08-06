package walletutils_test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/processor/instructions/walletutils"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/constants"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	cwallet "github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/stretchr/testify/require"
)

func TestKeyGenerate(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	var walletId = common.HexToHash("0xabcdef")
	var keyId = uint64(1)
	err := node.InitNode(node.ZeroState{})
	require.NoError(t, err)
	teeId := node.TeeID()
	numAdmins := 3
	adminPubKeys := make([]*ecdsa.PublicKey, numAdmins)
	adminPrivKeys := make([]*ecdsa.PrivateKey, numAdmins)
	for i := range numAdmins {
		adminPrivKeys[i], err = crypto.GenerateKey()
		require.NoError(t, err)
		adminPubKeys[i] = &adminPrivKeys[i].PublicKey
	}
	adminWalletPublicKeys := make([]cwallet.PublicKey, len(adminPubKeys))
	for i, pubKey := range adminPubKeys {
		pk := types.PubKeyToStruct(pubKey)
		adminWalletPublicKeys[i] = cwallet.PublicKey{
			X: pk.X,
			Y: pk.Y,
		}
	}

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, _, err = testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)
	require.NoError(t, err)

	originalMessage := cwallet.ITeeWalletKeyManagerKeyGenerate{
		TeeId:    teeId,
		WalletId: walletId,
		KeyId:    keyId,
		OpType:   constants.XRP.Hash(),
		ConfigConstants: cwallet.ITeeWalletKeyManagerKeyConfigConstants{
			OpTypeConstants:    make([]byte, 0),
			AdminsPublicKeys:   adminWalletPublicKeys,
			AdminsThreshold:    uint64(len(adminWalletPublicKeys)),
			Cosigners:          make([]common.Address, 0),
			CosignersThreshold: 0,
		},
	}
	originalMessageEncoded, err := abi.Arguments{cwallet.MessageArguments[constants.KeyGenerate]}.Pack(originalMessage)
	require.NoError(t, err)

	instructionId, err := utils.GenerateRandom()
	require.NoError(t, err)
	instructionDataFixed := instruction.DataFixed{
		InstructionID:          instructionId,
		TeeID:                  teeId,
		RewardEpochID:          epochId,
		OPType:                 constants.Wallet.Hash(),
		OPCommand:              constants.KeyGenerate.Hash(),
		OriginalMessage:        originalMessageEncoded,
		AdditionalFixedMessage: nil,
	}

	response, err := walletutils.NewWallet(&instructionDataFixed)
	if err != nil {
		t.Fatalf("Failed to sign the payment transaction: %v", err)
	}

	walletExistenceProof, err := types.ExtractKeyExistence(response)
	require.NoError(t, err)

	require.Equal(t, teeId, walletExistenceProof.TeeId)
	require.Equal(t, [32]byte(walletId), walletExistenceProof.WalletId)
	require.Equal(t, keyId, walletExistenceProof.KeyId)
	// todo: check response
}
