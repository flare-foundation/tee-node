package policy

import (
	"crypto/ecdsa"
	"encoding/hex"
	"tee-node/api/types"
	"tee-node/pkg/tee/settings"
	"tee-node/pkg/tee/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

func InitializePolicyRequest(initialPolicyBytes []byte, newPolicyRequests []types.MultiSignedPolicy, publicKeys []types.ECDSAPublicKey) error {
	var err error
	var currentPolicy *SigningPolicy
	var currentPolicyHash []byte
	var pubKeysMap map[common.Address]*ecdsa.PublicKey

	if len(publicKeys) == 0 {
		err = errors.New("no public keys given")
		goto finalize
	}

	_, err = GetActiveSigningPolicy()
	if err == nil {
		err = errors.New("policy already initialized")
		goto finalize
	}

	// no other process should be touching signingPoliciesStorage during this execution
	signingPoliciesStorage.Lock()
	defer signingPoliciesStorage.Unlock()

	// Initialize the original signing policy and store it in the map
	currentPolicy, err = DecodeSigningPolicy(initialPolicyBytes)
	if err != nil {
		goto finalize
	}
	currentPolicyHash = SigningPolicyBytesToHash(initialPolicyBytes)
	// Check that the policy matches the initial policy in the config file
	if settings.InitialPolicyHash != hex.EncodeToString(currentPolicyHash) && settings.Mode == 0 {
		err = errors.New("policy does not match the initial policy in the config file")
		goto finalize
	}

	SetActiveSigningPolicy(currentPolicy)

	// Go through the policies for each reward epoch and update the current policy
	for _, policyRequest := range newPolicyRequests {
		currentPolicy, err = ProcessUpdatePolicyRequest(policyRequest)
		if err != nil {
			goto finalize
		}
		SetActiveSigningPolicy(currentPolicy)
	}

	// Add public keys to the last policy
	pubKeysMap, err = ProcessPolicyPublicKeys(publicKeys, signingPoliciesStorage.ActiveSigningPolicy)
	if err != nil {
		goto finalize
	}
	SetActiveSigningPolicyPublicKeys(pubKeysMap)

finalize:
	if err != nil {
		DestroyState()
		return err
	}

	return nil
}

func UpdatePolicyRequest(newPolicyRequest types.MultiSignedPolicy, publicKeys []types.ECDSAPublicKey) error {
	signingPoliciesStorage.Lock()
	defer signingPoliciesStorage.Unlock()
	newPolicy, err := ProcessUpdatePolicyRequest(newPolicyRequest)
	if err != nil {
		return err
	}
	pubKeysMap, err := ProcessPolicyPublicKeys(publicKeys, newPolicy)
	if err != nil {
		return err
	}

	SetActiveSigningPolicyAndPubKeys(newPolicy, pubKeysMap)

	return nil
}

// only called while signingPoliciesStorage is locked
func ProcessUpdatePolicyRequest(policyRequest types.MultiSignedPolicy) (*SigningPolicy, error) {
	sigPolicy, err := DecodeSigningPolicy(policyRequest.PolicyBytes)
	if err != nil {
		return nil, err
	}

	activeSigningPolicy := signingPoliciesStorage.ActiveSigningPolicy
	if sigPolicy.RewardEpochId != activeSigningPolicy.RewardEpochId+1 {
		return nil, errors.New("policy is not active")
	}

	signers := make(map[common.Address][]byte)
	for _, sig := range policyRequest.Signatures {
		providerAddress, err := utils.CheckSignature(SigningPolicyBytesToHash(policyRequest.PolicyBytes), sig.Signature, activeSigningPolicy.Voters)
		if err != nil {
			return nil, err
		}
		signers[providerAddress] = sig.Signature
	}

	if WeightOfSigners(signers, activeSigningPolicy) < activeSigningPolicy.Threshold {
		return nil, errors.New("threshold for updating policy not reached")
	}

	return sigPolicy, nil
}

func ProcessPolicyPublicKeys(publicKeys []types.ECDSAPublicKey, sigPolicy *SigningPolicy) (map[common.Address]*ecdsa.PublicKey, error) {
	if len(publicKeys) != len(sigPolicy.Voters) {
		return nil, errors.New("the number of public keys and the number of voters do not match")
	}
	pubKeysMap := make(map[common.Address]*ecdsa.PublicKey)
	for i, pubKey := range publicKeys {
		pubKeyECDSA, err := types.ParsePubKey(pubKey)
		if err != nil {
			return nil, err
		}
		address := crypto.PubkeyToAddress(*pubKeyECDSA)
		if address != sigPolicy.Voters[i] {
			return nil, errors.New("public key and address do not match")
		}

		pubKeysMap[address] = pubKeyECDSA
	}

	return pubKeysMap, nil
}
