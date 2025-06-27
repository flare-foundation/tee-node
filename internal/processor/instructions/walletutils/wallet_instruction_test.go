package walletutils_test

import (
	"crypto/ecdsa"
	"math/big"
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
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	walletcommon "github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/stretchr/testify/require"
)

func TestKeyGenerate(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	var walletId = common.HexToHash("0xabcdef")
	var keyId = uint64(1)
	err := node.InitNode()
	require.NoError(t, err)
	teeId := node.GetTeeId()
	numAdmins := 3
	adminsPubKeys := make([]*ecdsa.PublicKey, numAdmins)
	adminsPrivKeys := make([]*ecdsa.PrivateKey, numAdmins)
	for i := range numAdmins {
		adminsPrivKeys[i], err = crypto.GenerateKey()
		require.NoError(t, err)
		adminsPubKeys[i] = &adminsPrivKeys[i].PublicKey
	}
	adminsWalletPublicKeys := make([]walletcommon.PublicKey, len(adminsPubKeys))
	for i, pubKey := range adminsPubKeys {
		adminsWalletPublicKeys[i] = walletcommon.PublicKey(types.PubKeyToStruct(pubKey))
	}

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	originalMessage := walletcommon.ITeeWalletKeyManagerKeyGenerate{
		TeeId:    teeId,
		WalletId: walletId,
		KeyId:    keyId,
		OpType:   utils.StringToOpHash("WALLET"),
		ConfigConstants: walletcommon.ITeeWalletKeyManagerKeyConfigConstants{
			OpTypeConstants:    make([]byte, 0),
			AdminsPublicKeys:   adminsWalletPublicKeys,
			AdminsThreshold:    uint64(len(adminsWalletPublicKeys)),
			Cosigners:          make([]common.Address, 0),
			CosignersThreshold: 0,
		},
	}
	originalMessageEncoded, err := abi.Arguments{walletcommon.MessageArguments[constants.KeyGenerate]}.Pack(originalMessage)
	require.NoError(t, err)

	instructionId, err := utils.GenerateRandom()
	require.NoError(t, err)
	instructionDataFixed := instruction.DataFixed{
		InstructionID:          instructionId,
		TeeID:                  teeId,
		RewardEpochID:          big.NewInt(int64(epochId)),
		OPType:                 utils.StringToOpHash("WALLET"),
		OPCommand:              utils.StringToOpHash("KEY_GENERATE"),
		OriginalMessage:        originalMessageEncoded,
		AdditionalFixedMessage: nil,
	}

	response, err := walletutils.NewWallet(&instructionDataFixed)
	if err != nil {
		t.Fatalf("Failed to sign the payment transaction: %v", err)
	}

	walletExistenceProof, err := structs.Decode[walletcommon.ITeeWalletKeyManagerKeyExistence](walletcommon.KeyExistenceStructArg, response)
	require.NoError(t, err)

	require.Equal(t, teeId, walletExistenceProof.TeeId)
	require.Equal(t, [32]byte(walletId), walletExistenceProof.WalletId)
	require.Equal(t, keyId, walletExistenceProof.KeyId)
	// todo: check response
}
