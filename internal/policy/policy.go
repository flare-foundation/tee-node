package policy

import (
	"crypto/ecdsa"
	"slices"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/pkg/errors"
)

var Storage *SigningPoliciesStorage

func init() {
	Storage = InitSigningPoliciesStorage()
}

// SigningPoliciesStorage holds policies. Since policies are being added and the active policy is being modified,
// we need mutex. Note that when a policy is added in a the SigningPolicies map, it is never modified.
type SigningPoliciesStorage struct {
	initialPolicyID   uint32
	initialPolicyHash common.Hash

	active           *policy.SigningPolicy // Current policy that is being used for signing
	activePublicKeys map[common.Address]*ecdsa.PublicKey
	signingPolicies  map[uint32]*policy.SigningPolicy // map of rewardEpochId to policy

	sync.RWMutex
}

func InitSigningPoliciesStorage() *SigningPoliciesStorage {
	return &SigningPoliciesStorage{signingPolicies: make(map[uint32]*policy.SigningPolicy)}
}

func (s *SigningPoliciesStorage) SetInitialPolicy(policy *policy.SigningPolicy, addressesToPublicKeys map[common.Address]*ecdsa.PublicKey) error {
	if s.active != nil {
		return errors.New("signing policy already initialized")
	}

	s.initialPolicyID = policy.RewardEpochID
	s.initialPolicyHash = common.Hash(policy.Hash())

	err := s.SetActiveSigningPolicy(policy)
	if err != nil {
		return err
	}
	err = s.SetActiveSigningPolicyPublicKeys(addressesToPublicKeys)
	if err != nil {
		return err
	}

	return nil
}

func (s *SigningPoliciesStorage) InitialPolicyIdAndHash() (uint32, common.Hash) {
	return s.initialPolicyID, s.initialPolicyHash
}

func (s *SigningPoliciesStorage) ActiveSigningPolicy() (*policy.SigningPolicy, error) {
	if s.active == nil {
		return nil, errors.New("signing policy not initialized")
	}

	// make a copy
	activeSigningPolicy := *s.active

	return &activeSigningPolicy, nil
}

// SigningPolicyInfo returns ids and hashes of initial and active signing policies.
func SigningPolicyInfo() (uint32, common.Hash, uint32, common.Hash) {
	initialID, initialHash := Storage.InitialPolicyIdAndHash()
	actPolicy, err := Storage.ActiveSigningPolicy()

	if err != nil {
		return initialID, initialHash, initialID, initialHash
	} else {
		return initialID, initialHash, actPolicy.RewardEpochID, common.Hash(actPolicy.Hash())
	}
}

// SigningPolicy returns the signing policy for the reward epoch id.
func (s *SigningPoliciesStorage) SigningPolicy(epochId uint32) (*policy.SigningPolicy, error) {
	policy, ok := s.signingPolicies[epochId]
	if !ok {
		return nil, errors.New("policy of the given reward epoch not in the storage")
	}

	// make a copy
	returnPolicy := *policy

	return &returnPolicy, nil
}

func (s *SigningPoliciesStorage) SetActiveSigningPolicy(policy *policy.SigningPolicy) error {
	if s.initialPolicyHash.Cmp(common.Hash{}) == 0 {
		return errors.New("signing policy not initialized yet")
	}

	s.active = policy
	s.signingPolicies[policy.RewardEpochID] = policy
	return nil
}

func (s *SigningPoliciesStorage) SetActiveSigningPolicyPublicKeys(addressesToPublicKeys map[common.Address]*ecdsa.PublicKey) error {
	if s.initialPolicyHash.Cmp(common.Hash{}) == 0 {
		return errors.New("signing policy not initialized yet")
	}
	s.activePublicKeys = addressesToPublicKeys
	return nil
}

func (s *SigningPoliciesStorage) GetActiveSigningPolicyPublicKeysSlice() ([]*ecdsa.PublicKey, error) {
	return toSigningPolicyPublicKeysSlice(s.active, s.activePublicKeys)
}

func toSigningPolicyPublicKeysSlice(policy *policy.SigningPolicy, pubKeysMap map[common.Address]*ecdsa.PublicKey) ([]*ecdsa.PublicKey, error) {
	pubKeys := make([]*ecdsa.PublicKey, len(policy.Voters.Voters()))
	var ok bool
	for i, address := range policy.Voters.Voters() {
		pubKeys[i], ok = pubKeysMap[address]
		// this should never happen
		if !ok {
			return nil, errors.New("address not in policy public key map, internal error")
		}
	}

	return pubKeys, nil
}

func WeightOfSigners(signers []common.Address, signingPolicy *policy.SigningPolicy) uint16 {
	currentWeight := uint16(0)
	for i, voter := range signingPolicy.Voters.Voters() {
		if ok := slices.Contains(signers, voter); ok {
			currentWeight += signingPolicy.Voters.VoterWeight(i)
		}
	}

	return currentWeight
}

func (s *SigningPoliciesStorage) DestroyState() {
	s.active = nil
	s.signingPolicies = make(map[uint32]*policy.SigningPolicy)
	s.activePublicKeys = nil

	s.initialPolicyID = 0
	s.initialPolicyHash = common.Hash{}
}
