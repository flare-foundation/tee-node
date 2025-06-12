package walletsinstruction_test

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"tee-node/api/types"
	"tee-node/pkg/tee/node"
	"tee-node/pkg/tee/processor/instructions/walletsinstruction"
	"tee-node/pkg/tee/utils"
	"tee-node/testutils"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
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
	adminsWalletPublicKeys := make([]wallet.PublicKey, len(adminsPubKeys))
	for i, pubKey := range adminsPubKeys {
		adminsWalletPublicKeys[i] = wallet.PublicKey(types.PubKeyToStruct(pubKey))
	}

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	originalMessage := wallet.ITeeWalletKeyManagerKeyGenerate{
		TeeId:    teeId,
		WalletId: walletId,
		KeyId:    keyId,
		OpType:   utils.StringToOpHash("WALLET"),
		ConfigConstants: wallet.ITeeWalletKeyManagerKeyConfigConstants{
			OpTypeConstants:    make([]byte, 0),
			AdminsPublicKeys:   adminsWalletPublicKeys,
			AdminsThreshold:    uint64(len(adminsWalletPublicKeys)),
			Cosigners:          make([]common.Address, 0),
			CosignersThreshold: 0,
		},
	}
	originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[wallet.KeyGenerate]}.Pack(originalMessage)
	require.NoError(t, err)

	instructionId, _ := testutils.GenerateRandomBytes(32)

	instructionDataFixed := instruction.DataFixed{
		InstructionID:          common.HexToHash(hex.EncodeToString(instructionId)),
		TeeID:                  teeId,
		RewardEpochID:          big.NewInt(int64(epochId)),
		OPType:                 utils.StringToOpHash("WALLET"),
		OPCommand:              utils.StringToOpHash("KEY_GENERATE"),
		OriginalMessage:        originalMessageEncoded,
		AdditionalFixedMessage: nil,
	}

	response, err := walletsinstruction.NewWallet(&instructionDataFixed)
	if err != nil {
		t.Fatalf("Failed to sign the payment transaction: %v", err)
	}

	var walletExistenceProof wallet.ITeeWalletKeyManagerKeyExistence
	err = json.Unmarshal(response, &walletExistenceProof)
	require.NoError(t, err)

	require.Equal(t, teeId, walletExistenceProof.TeeId)
	require.Equal(t, [32]byte(walletId), walletExistenceProof.WalletId)
	require.Equal(t, keyId, walletExistenceProof.KeyId)
	// todo: check response
}
