package policy

import (
	"context"
	"encoding/hex"
	"tee-node/internal/policy"

	api "tee-node/api/types"
	pd "tee-node/internal/policy"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
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
}

const (
	signNewSigningPolicy = "signNewSigningPolicy"
	maxInt               = int64(^uint64(0) >> 1)
)

var (
	signingPolicyInitializedEventSel common.Hash
	AttestationRequestEventSel       common.Hash
	systemABI                        *abi.ABI
	signNewSigningPolicyAbiArgs      abi.Arguments
	signNewSigningPolicyFuncSel      [4]byte
)

func init() {
	relayABI, err := relay.RelayMetaData.GetAbi()
	if err != nil {
		logger.Panic("cannot get relayAby:", err)
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
}

// FetchPolicyHistory extracts all the data involving policies from the database
func FetchPolicyHistory(ctx context.Context, params *PolicyHistoryParams, db *gorm.DB) ([]*relay.RelaySigningPolicyInitialized, map[string][]*policy.Signature, error) {
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

	hashToSignatures := make(map[string][]*policy.Signature)
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
		newSigningPolicyHashBytes := *abi.ConvertType(signNewSigningPolicyInputBytesArray[1], new([32]byte)).(*[32]byte)
		newSigningPolicyHash := hex.EncodeToString(newSigningPolicyHashBytes[:])
		systemManageSignature := *abi.ConvertType(signNewSigningPolicyInputBytesArray[2], new(system.IFlareSystemsManagerSignature)).(*system.IFlareSystemsManagerSignature)

		sigBytes := make([]byte, 65)
		copy(sigBytes[0:32], systemManageSignature.R[:])
		copy(sigBytes[32:64], systemManageSignature.S[:])
		sigBytes[64] = systemManageSignature.V - 27
		pubKeyBytes, err := crypto.Ecrecover(accounts.TextHash(newSigningPolicyHashBytes[:]), sigBytes)
		if err != nil {
			return nil, nil, err
		}
		sig := policy.Signature{Sig: sigBytes, PubKey: pubKeyBytes}

		if _, ok := hashToSignatures[newSigningPolicyHash]; !ok {
			hashToSignatures[newSigningPolicyHash] = make([]*policy.Signature, 0)
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

func CreateSigningRequest(policies []*relay.RelaySigningPolicyInitialized, signatures map[string][]*policy.Signature) (*api.InitializePolicyRequest, error) {
	policyRequests := []*api.SignNewPolicyRequest{}

	// Replay policy signing from the second policy onwards
	for _, policy := range policies[1:] {
		policyHash := hex.EncodeToString(pd.SigningPolicyHash(policy.SigningPolicyBytes))
		policySignatures := signatures[policyHash]
		policyDecoded, err := pd.DecodeSigningPolicy(policy.SigningPolicyBytes)
		if err != nil {
			return nil, err
		}

		policySignatureRequests := []*api.SignatureMessage{}
		for _, sig := range policySignatures {
			pubKey, err := crypto.UnmarshalPubkey(sig.PubKey)
			if err != nil {
				return nil, err
			}

			weight := pd.GetSignerWeight(pubKey, policyDecoded)
			if weight == 0 {
				continue
			}

			mes := api.SignatureMessage{
				PublicKey: &api.ECDSAPublicKey{
					X: pubKey.X.String(),
					Y: pubKey.Y.String(),
				},
				Signature: sig.Sig,
			}
			policySignatureRequests = append(policySignatureRequests, &mes)
		}

		signNewPolicyRequest := api.SignNewPolicyRequest{
			PolicyBytes:             policy.SigningPolicyBytes,
			PolicySignatureMessages: policySignatureRequests,
		}

		policyRequests = append(policyRequests, &signNewPolicyRequest)
	}
	req := &api.InitializePolicyRequest{
		InitialPolicyBytes: policies[0].SigningPolicyBytes,
		NewPolicyRequests:  policyRequests,
	}

	return req, nil
}
