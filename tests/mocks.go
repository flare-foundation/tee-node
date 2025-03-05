package utils

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"tee-node/internal/policy"
	"tee-node/internal/requests"
	"tee-node/internal/service/instructionservice/walletsservice"
	"tee-node/internal/utils"
	"testing"

	api "tee-node/api/types"

	"github.com/stretchr/testify/require"
)

// Todo: I want to extract some logic for generating mock policies, wallets, etc. into this file.

func BuildMockInstruction(OpType string, OpCommand string, request interface{}, privKey *ecdsa.PrivateKey, teeId, instructionId string) (*api.Instruction, error) {

	OriginalMessage, err := json.Marshal(request)
	if err != nil {
		fmt.Printf("Error marshalling request: %v\n", err)
		return nil, err
	}

	instructionData := api.InstructionData{
		InstructionId:             instructionId,
		TeeId:                     teeId,
		RewardEpochid:             policy.ActiveSigningPolicy.RewardEpochId,
		OpType:                    OpType,
		OpCommand:                 OpCommand,
		OriginalMessage:           OriginalMessage,
		AdditionalFixedMessage:    []byte(""),
		AdditionalVariableMessage: []byte(""),
	}

	nonceBytes, _ := utils.GenerateRandomBytes(32)

	sig, err := requests.Sign(&instructionData, privKey)
	if err != nil {
		fmt.Printf("Error signing instruction: %v\n", err)
		return nil, err
	}

	return &api.Instruction{
		Challenge: hex.EncodeToString(nonceBytes),
		Data:      &instructionData,
		Signature: sig,
	}, nil

}

func CreateMockWallet(t *testing.T, walletName string, privKeys []*ecdsa.PrivateKey) {
	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	instruction, err := BuildMockInstruction("WALLET",
		"KEY_GENERATE",
		api.NewWalletRequest{Name: walletName},
		privKeys[0],
		"1234",
		hex.EncodeToString(instructionIdBytes),
	)
	require.NoError(t, err)

	err = walletsservice.NewWallet(instruction.Data)

	require.NoError(t, err)

}
