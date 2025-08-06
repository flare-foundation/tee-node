package policyutils

import (
	"crypto/ecdsa"
	"encoding/json"

	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	commonpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

func InitializePolicy(message []byte) error {
	var req types.InitializePolicyRequest
	err := json.Unmarshal(message, &req)
	if err != nil {
		return err
	}

	var initialPolicy *commonpolicy.SigningPolicy
	var pubKeysMap map[common.Address]*ecdsa.PublicKey

	// no other process should be touching signingPoliciesStorage during this execution
	policy.Storage.Lock()
	defer policy.Storage.Unlock()

	_, err = policy.Storage.ActiveSigningPolicy()
	if err == nil {
		err = errors.New("policy already initialized")
		goto finalize
	}

	// Initialize the original signing policy and store it in the map
	initialPolicy, _, err = commonpolicy.FromRawBytes(req.InitialPolicyBytes)
	if err != nil {
		goto finalize
	}

	// Add public keys to the last policy
	pubKeysMap, err = processPolicyPublicKeys(req.PublicKeys, initialPolicy)
	if err != nil {
		goto finalize
	}
	err = policy.Storage.SetInitialPolicy(initialPolicy, pubKeysMap)
	if err != nil {
		goto finalize
	}

finalize:
	if err != nil {
		policy.Storage.DestroyState()
		return err
	}

	return nil
}

func UpdatePolicy(message []byte) error {
	var updatePolicyRequest types.UpdatePolicyRequest
	err := json.Unmarshal(message, &updatePolicyRequest)
	if err != nil {
		return err
	}

	policy.Storage.Lock()
	defer policy.Storage.Unlock()

	newPolicy, err := processUpdatePolicyRequest(updatePolicyRequest.NewPolicy)
	if err != nil {
		return err
	}
	pubKeysMap, err := processPolicyPublicKeys(updatePolicyRequest.PublicKeys, newPolicy)
	if err != nil {
		return err
	}

	err = policy.Storage.SetActiveSigningPolicy(newPolicy)
	if err != nil {
		return err
	}
	err = policy.Storage.SetActiveSigningPolicyPublicKeys(pubKeysMap)
	if err != nil {
		return err
	}

	return nil
}

// only called while signingPoliciesStorage is locked
func processUpdatePolicyRequest(policyRequest types.MultiSignedPolicy) (*commonpolicy.SigningPolicy, error) {
	sigPolicy, _, err := commonpolicy.FromRawBytes(policyRequest.PolicyBytes)
	if err != nil {
		return nil, err
	}

	activeSigningPolicy, err := policy.Storage.ActiveSigningPolicy()
	if err != nil {
		return nil, err
	}
	if sigPolicy.RewardEpochID != activeSigningPolicy.RewardEpochID+1 {
		return nil, errors.New("policy is not active")
	}

	hash := commonpolicy.Hash(policyRequest.PolicyBytes)

	signers := make([]common.Address, len(policyRequest.Signatures))
	for i, sig := range policyRequest.Signatures {
		providerAddress, err := utils.CheckSignature(hash, sig, activeSigningPolicy.Voters.Voters())
		if err != nil {
			return nil, err
		}
		signers[i] = providerAddress
	}

	if policy.WeightOfSigners(signers, activeSigningPolicy) <= activeSigningPolicy.Threshold {
		return nil, errors.New("threshold for updating policy not reached")
	}

	return sigPolicy, nil
}

func processPolicyPublicKeys(publicKeys []types.PublicKey, sigPolicy *commonpolicy.SigningPolicy) (map[common.Address]*ecdsa.PublicKey, error) {
	if len(publicKeys) != len(sigPolicy.Voters.Voters()) {
		return nil, errors.New("the number of public keys and the number of voters do not match")
	}
	pubKeysMap := make(map[common.Address]*ecdsa.PublicKey)
	for i, pubKey := range publicKeys {
		pubKeyECDSA, err := types.ParsePubKey(pubKey)
		if err != nil {
			return nil, err
		}
		address := crypto.PubkeyToAddress(*pubKeyECDSA)
		if address != sigPolicy.Voters.Voters()[i] {
			return nil, errors.New("public key and address do not match")
		}

		pubKeysMap[address] = pubKeyECDSA
	}

	return pubKeysMap, nil
}
