package policy

import (
	"crypto/ecdsa"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var signingPoliciesStorage *SigningPoliciesStorage

func init() {
	signingPoliciesStorage = InitSigningPoliciesStorage()
}

// SigningPoliciesStorage holds policies. Since policies are being added and the active policy is being modified,
// we need mutex. Note that when a policy is added in a the SigningPolicies map, it is never modified.
type SigningPoliciesStorage struct {
	ActiveSigningPolicy           *SigningPolicy // Current policy that is being used for signing
	ActiveSigningPolicyPublicKeys map[common.Address]*ecdsa.PublicKey
	SigningPolicies               map[uint32]*SigningPolicy // map of rewardEpochId to policy

	sync.RWMutex
}

func InitSigningPoliciesStorage() *SigningPoliciesStorage {
	return &SigningPoliciesStorage{SigningPolicies: make(map[uint32]*SigningPolicy)}
}

func GetActiveSigningPolicy() *SigningPolicy {
	signingPoliciesStorage.RLock()
	defer signingPoliciesStorage.RUnlock()

	return signingPoliciesStorage.ActiveSigningPolicy
}

func GetActiveSigningPolicyPublicKeysMap() map[common.Address]*ecdsa.PublicKey {
	signingPoliciesStorage.RLock()
	defer signingPoliciesStorage.RUnlock()

	return signingPoliciesStorage.ActiveSigningPolicyPublicKeys
}

func GetSigningPolicyPublicKeys(policy *SigningPolicy, pubKeysMap map[common.Address]*ecdsa.PublicKey) ([]*ecdsa.PublicKey, error) {
	pubKeys := make([]*ecdsa.PublicKey, len(policy.Voters))
	// todo: check to prevent fail
	var ok bool
	for i, address := range policy.Voters {
		pubKeys[i], ok = pubKeysMap[address]
		// this should never happen
		if !ok {
			return nil, errors.New("address not in policy public key map, internal error")
		}
	}

	return pubKeys, nil
}

func SigningPolicyBytesToHash(signingPolicy []byte) []byte {
	if len(signingPolicy)%32 != 0 {
		signingPolicy = append(signingPolicy, make([]byte, 32-len(signingPolicy)%32)...)
	}
	hash := crypto.Keccak256(signingPolicy[:32], signingPolicy[32:64])
	for i := 2; i < len(signingPolicy)/32; i++ {
		hash = crypto.Keccak256(hash, signingPolicy[i*32:(i+1)*32])
	}
	return hash
}

func SigningPolicyToHash(signingPolicy *SigningPolicy) ([]byte, error) {
	signingPolicyBytes, err := EncodeSigningPolicy(signingPolicy)
	if err != nil {
		return nil, err
	}

	return SigningPolicyBytesToHash(signingPolicyBytes), nil
}

func WeightOfSigners(signers map[common.Address][]byte, signingPolicy *SigningPolicy) uint16 {
	currentWeight := uint16(0)
	for i, voter := range signingPolicy.Voters {
		if _, ok := signers[voter]; ok {
			currentWeight += signingPolicy.Weights[i]
		}
	}

	return currentWeight
}

func VerifyPolicyFreshness(sigPolicy *SigningPolicy, currentRewardEpochId uint32) error {
	// Verify the policy is new and for a valid rewards epoch Id
	if sigPolicy.RewardEpochId <= currentRewardEpochId {
		return status.Error(codes.InvalidArgument, "Trying to initialize policy for an invalid reward epoch Id")
	}

	signingPoliciesStorage.RLock()
	defer signingPoliciesStorage.RUnlock()
	if _, ok := signingPoliciesStorage.SigningPolicies[sigPolicy.RewardEpochId]; ok {
		return status.Error(codes.InvalidArgument, "Policy already exists for the reward epoch")
	}

	return nil
}

func SetActiveSigningPolicyAndPubKeys(policy *SigningPolicy, addressesToPublicKeys map[common.Address]*ecdsa.PublicKey) {
	signingPoliciesStorage.Lock()
	defer signingPoliciesStorage.Unlock()

	signingPoliciesStorage.ActiveSigningPolicy = policy
	signingPoliciesStorage.SigningPolicies[policy.RewardEpochId] = policy
	signingPoliciesStorage.ActiveSigningPolicyPublicKeys = addressesToPublicKeys
}

// SetActiveSigningPolicy happens only at initialize policy stage, hence does not need locking.
func SetActiveSigningPolicy(policy *SigningPolicy) {
	signingPoliciesStorage.ActiveSigningPolicy = policy
	signingPoliciesStorage.SigningPolicies[policy.RewardEpochId] = policy
}

// SetActiveSigningPolicyPublicKeys happens only at initialize policy stage, hence does not need locking.
func SetActiveSigningPolicyPublicKeys(addressesToPublicKeys map[common.Address]*ecdsa.PublicKey) {
	signingPoliciesStorage.ActiveSigningPolicyPublicKeys = addressesToPublicKeys
}

// todo mutex
func GetSigningPolicy(epochId uint32) *SigningPolicy {
	signingPoliciesStorage.RLock()
	defer signingPoliciesStorage.RUnlock()
	policy, ok := signingPoliciesStorage.SigningPolicies[epochId]
	if !ok {
		return nil
	}
	return policy
}

func DestroyState() {
	signingPoliciesStorage.ActiveSigningPolicy = nil
	signingPoliciesStorage.SigningPolicies = make(map[uint32]*SigningPolicy)
	signingPoliciesStorage.ActiveSigningPolicyPublicKeys = nil
}
