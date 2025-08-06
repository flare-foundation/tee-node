package policy

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"testing"

	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/types"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/contracts/registry"
	"github.com/flare-foundation/go-flare-common/pkg/contracts/relay"
	"github.com/flare-foundation/go-flare-common/pkg/contracts/system"
	"github.com/flare-foundation/go-flare-common/pkg/database"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	common_policy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"gorm.io/gorm"
)

type PolicyHistoryParams struct {
	RelayContractAddress              common.Address
	FlareSystemManagerContractAddress common.Address
	FlareVoterRegistryContractAddress common.Address
}

const (
	signNewSigningPolicy = "signNewSigningPolicy"
	registerVoter        = "registerVoter"
	maxInt               = int64(^uint64(0) >> 1)
	maxUInt              = ^uint64(0)
)

var (
	signingPolicyInitializedEventSel common.Hash
	AttestationRequestEventSel       common.Hash
	systemABI                        *abi.ABI
	signNewSigningPolicyAbiArgs      abi.Arguments
	signNewSigningPolicyFuncSel      [4]byte
	voterRegisteredEventSel          common.Hash
	registerVoterFuncSel             [4]byte
	registerVoterAbiArgs             abi.Arguments
	uint32Ty, _                      = abi.NewType("uint32", "", nil)
	addressTy, _                     = abi.NewType("address", "", nil)
)

func init() {
	relayABI, err := relay.RelayMetaData.GetAbi()
	if err != nil {
		logger.Panic("cannot get relay Abi:", err)
	}
	signingPolicyEvent, ok := relayABI.Events["SigningPolicyInitialized"]
	if !ok {
		logger.Panic("cannot get SigningPolicyInitialized event:", err)
	}
	signingPolicyInitializedEventSel = signingPolicyEvent.ID

	systemABI, err = system.FlareSystemsManagerMetaData.GetAbi()
	if err != nil {
		logger.Panic("cannot get submission ABI:", err)
	}
	copy(signNewSigningPolicyFuncSel[:], systemABI.Methods[signNewSigningPolicy].ID[:4])
	signNewSigningPolicyAbiArgs = systemABI.Methods[signNewSigningPolicy].Inputs

	voterRegistryABI, err := registry.RegistryMetaData.GetAbi()
	if err != nil {
		logger.Panic("cannot get registry abi:", err)
	}
	voterRegisteredEvent, ok := voterRegistryABI.Events["VoterRegistered"]
	if !ok {
		logger.Panic("cannot get VoterRegistered event:", err)
	}
	voterRegisteredEventSel = voterRegisteredEvent.ID
	copy(registerVoterFuncSel[:], voterRegistryABI.Methods[registerVoter].ID[:4])
	registerVoterAbiArgs = voterRegistryABI.Methods[registerVoter].Inputs
}

// FetchPolicyHistory extracts all the data involving policies from the database
func FetchPolicyHistory(ctx context.Context, params *PolicyHistoryParams, db *gorm.DB) ([]*relay.RelaySigningPolicyInitialized, map[common.Hash][]*PolicySignature, error) {
	logsParams := database.LogsParams{
		Address: params.RelayContractAddress,
		Topic0:  signingPolicyInitializedEventSel,
		From:    0,
		To:      maxInt,
	}

	logs, err := database.FetchLogsByAddressAndTopic0Timestamp(
		ctx, db, logsParams,
	)
	if err != nil {
		return nil, nil, err
	}

	txsParams := database.TxParams{
		ToAddress:   params.FlareSystemManagerContractAddress,
		FunctionSel: signNewSigningPolicyFuncSel,
		From:        0,
		To:          maxInt,
	}
	txs, err := database.FetchTransactionsByAddressAndSelectorTimestamp(
		ctx, db, txsParams,
	)
	if err != nil {
		return nil, nil, err
	}

	hashToSignatures := make(map[common.Hash][]*PolicySignature)
	for _, tx := range txs {
		inputBytes, err := hex.DecodeString(tx.Input)
		if err != nil {
			return nil, nil, err
		}
		inputBytes = inputBytes[4:]

		signNewSigningPolicyInputBytesArray, err := signNewSigningPolicyAbiArgs.Unpack(inputBytes)
		if err != nil {
			return nil, nil, err
		}
		// rewardEpochId := *abi.ConvertType(signNewSigningPolicyInputBytesArray[0], new(*big.Int)).(**big.Int)
		newSigningPolicyHashBytes := *abi.ConvertType(signNewSigningPolicyInputBytesArray[1], new([32]byte)).(*[32]byte) //nolint:forcetypeassert // type never changes and used only for test
		newSigningPolicyHash := common.BytesToHash(newSigningPolicyHashBytes[:])
		systemManageSignature := *abi.ConvertType(signNewSigningPolicyInputBytesArray[2], new(system.IFlareSystemsManagerSignature)).(*system.IFlareSystemsManagerSignature) //nolint:forcetypeassert // type never changes and used only for test

		sigBytes := make([]byte, 65)
		copy(sigBytes[0:32], systemManageSignature.R[:])
		copy(sigBytes[32:64], systemManageSignature.S[:])
		sigBytes[64] = systemManageSignature.V - 27
		pubKeyBytes, err := crypto.Ecrecover(accounts.TextHash(newSigningPolicyHashBytes[:]), sigBytes)
		if err != nil {
			return nil, nil, err
		}
		sig := PolicySignature{Sig: sigBytes, PubKey: pubKeyBytes}

		if _, ok := hashToSignatures[newSigningPolicyHash]; !ok {
			hashToSignatures[newSigningPolicyHash] = make([]*PolicySignature, 0)
		}
		hashToSignatures[newSigningPolicyHash] = append(hashToSignatures[newSigningPolicyHash], &sig)
	}

	policies := make([]*relay.RelaySigningPolicyInitialized, len(logs))
	for i, log := range logs {
		policies[i], err = common_policy.ParseSigningPolicyInitializedEvent(log)
		if err != nil {
			return nil, nil, err
		}
	}

	return policies, hashToSignatures, nil
}

type PolicySignature struct {
	Sig    []byte
	PubKey []byte
}

func CreateInitializePolicyAction(t *testing.T, policy *relay.RelaySigningPolicyInitialized, pubKeysMap map[common.Address]*ecdsa.PublicKey) (*types.Action, error) {
	pubKeys := make([]types.PublicKey, len(policy.Voters))
	for i, voter := range policy.Voters {
		pubKeys[i] = types.PubKeyToStruct(pubKeysMap[voter])
	}

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: policy.SigningPolicyBytes,
		PublicKeys:         pubKeys,
	}

	action := testutils.BuildMockQueuedAction(t, "POLICY", "INITIALIZE_POLICY", req)

	return action, nil
}

func FetchVoterRegisteredBlocksInfo(ctx context.Context, params *PolicyHistoryParams, db *gorm.DB, rewardEpochId uint32) (uint64, uint64, error) {
	logsParams := database.LogsParams{
		Address: params.FlareVoterRegistryContractAddress,
		Topic0:  voterRegisteredEventSel,
		From:    0,
		To:      maxInt,
	}

	logs, err := database.FetchLogsByAddressAndTopic0Timestamp(
		ctx, db, logsParams,
	)
	if err != nil {
		return 0, 0, err
	}

	minBlockNum := maxUInt
	maxBlockNum := uint64(0)
	for _, log := range logs {
		event, err := common_policy.ParseVoterRegisteredEvent(log)
		if err != nil {
			return 0, 0, err
		}
		if event.RewardEpochId == rewardEpochId {
			if log.BlockNumber < minBlockNum {
				minBlockNum = log.BlockNumber
			}
			if log.BlockNumber > maxBlockNum {
				maxBlockNum = log.BlockNumber
			}
		}
	}

	return minBlockNum, maxBlockNum, nil
}

func FetchVotersPublicKeysMap(ctx context.Context, params *PolicyHistoryParams, db *gorm.DB, minBlockNum, maxBlockNum uint64, rewardEpochId uint32) (map[common.Address]*ecdsa.PublicKey, error) {
	txsParams := database.TxParams{
		ToAddress:   params.FlareVoterRegistryContractAddress,
		FunctionSel: registerVoterFuncSel,
		From:        int64(minBlockNum) - 1,
		To:          int64(maxBlockNum),
	}
	txs, err := database.FetchTransactionsByAddressAndSelectorBlockNumber(
		ctx, db, txsParams,
	)
	if err != nil {
		return nil, err
	}

	addressToPubKey := make(map[common.Address]*ecdsa.PublicKey)
	for _, tx := range txs {
		inputBytes, err := hex.DecodeString(tx.Input)
		if err != nil {
			return nil, err
		}
		inputBytes = inputBytes[4:]

		registerVoterInputBytesArray, err := registerVoterAbiArgs.Unpack(inputBytes)
		if err != nil {
			return nil, err
		}
		if len(registerVoterInputBytesArray) != 2 {
			return nil, err
		}

		voterAddress := *abi.ConvertType(registerVoterInputBytesArray[0], new(common.Address)).(*common.Address)                                  //nolint:forcetypeassert // type never changes and used only for test
		signature := *abi.ConvertType(registerVoterInputBytesArray[1], new(registry.RegistryVoterRegistered)).(*registry.RegistryVoterRegistered) //nolint:forcetypeassert // type never changes and used only for test

		sigBytes := make([]byte, 65)
		copy(sigBytes[0:32], signature.Signature.R[:])
		copy(sigBytes[32:64], signature.Signature.S[:])
		sigBytes[64] = signature.Signature.V - 27

		arguments := abi.Arguments{{Type: uint32Ty}, {Type: addressTy}}

		toHash, err := arguments.Pack(rewardEpochId, voterAddress)
		if err != nil {
			return nil, err
		}

		pubKeyBytes, err := crypto.Ecrecover(accounts.TextHash(crypto.Keccak256(toHash)), sigBytes)
		if err != nil {
			return nil, err
		}

		pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
		if err != nil {
			return nil, err
		}
		signingAddress := crypto.PubkeyToAddress(*pubKey)
		addressToPubKey[signingAddress] = pubKey
	}

	return addressToPubKey, nil
}
