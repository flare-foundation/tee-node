package policy

import (
	"crypto/ecdsa"
	"errors"
	"slices"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/policy"
)

// Storage holds policies. Since policies are being added and the active policy is being modified,
// When a policy is added in a the SigningPolicies map, it is never modified.
type Storage struct {
	initialPolicyID   uint32
	initialPolicyHash common.Hash

	active           *policy.SigningPolicy // Current policy that is being used for signing
	activePublicKeys map[common.Address]*ecdsa.PublicKey
	signingPolicies  map[uint32]*policy.SigningPolicy // map of rewardEpochID to policy

	sync.RWMutex
}

// InitializeStorage returns an empty policy storage.
func InitializeStorage() *Storage {
	return &Storage{signingPolicies: make(map[uint32]*policy.SigningPolicy)}
}

// SetInitialPolicy stores the first signing policy and associated public keys.
//
// chainID binds the stored hash to the source chain; it must be the node's
// configured chain id, since go-verifier-api compares this value against the
// Relay's toSigningPolicyHash.
func (s *Storage) SetInitialPolicy(chainID uint64, policy *policy.SigningPolicy, addressesToPublicKeys map[common.Address]*ecdsa.PublicKey) error {
	if s.active != nil {
		return errors.New("signing policy already initialized")
	}

	s.initialPolicyID = policy.RewardEpochID
	s.initialPolicyHash = common.Hash(policy.ChainBoundHash(chainID))

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

// InitialPolicyIDAndHash returns the ID and hash of the first policy.
func (s *Storage) InitialPolicyIDAndHash() (uint32, common.Hash) {
	return s.initialPolicyID, s.initialPolicyHash
}

// ActiveSigningPolicy returns a copy of the currently active policy.
func (s *Storage) ActiveSigningPolicy() (*policy.SigningPolicy, error) {
	if s.active == nil {
		return nil, errors.New("signing policy not initialized")
	}

	// make a copy
	asp := *s.active

	return &asp, nil
}

// Info returns ids and hashes of initial and active signing policies.
//
// chainID must match the one SetInitialPolicy was given — the two hashes are
// compared against the same Relay.
func (s *Storage) Info(chainID uint64) (uint32, common.Hash, uint32, common.Hash) {
	initialID, initialHash := s.InitialPolicyIDAndHash()
	actPolicy, err := s.ActiveSigningPolicy()

	if err != nil {
		return initialID, initialHash, initialID, initialHash
	} else {
		return initialID, initialHash, actPolicy.RewardEpochID, common.Hash(actPolicy.ChainBoundHash(chainID))
	}
}

// SigningPolicy returns the signing policy for the reward epoch id.
func (s *Storage) SigningPolicy(epochID uint32) (*policy.SigningPolicy, error) {
	p, ok := s.signingPolicies[epochID]
	if !ok {
		return nil, errors.New("policy of the given reward epoch not in the storage")
	}

	// make a copy
	pCopy := *p

	return &pCopy, nil
}

// SetActiveSigningPolicy marks the provided policy as active.
func (s *Storage) SetActiveSigningPolicy(policy *policy.SigningPolicy) error {
	if s.initialPolicyHash.Cmp(common.Hash{}) == 0 {
		return errors.New("signing policy not initialized yet")
	}

	s.active = policy
	s.signingPolicies[policy.RewardEpochID] = policy
	return nil
}

// SetActiveSigningPolicyPublicKeys stores the public keys for the active policy.
func (s *Storage) SetActiveSigningPolicyPublicKeys(addressesToPublicKeys map[common.Address]*ecdsa.PublicKey) error {
	if s.initialPolicyHash.Cmp(common.Hash{}) == 0 {
		return errors.New("signing policy not initialized yet")
	}
	s.activePublicKeys = addressesToPublicKeys
	return nil
}

// ActiveSigningPolicyPublicKeys returns the public keys for the active policy in
// voter order.
func (s *Storage) ActiveSigningPolicyPublicKeys() ([]*ecdsa.PublicKey, error) {
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

// WeightOfSigners returns the weight of the signers in slice.
//
// If a signer is duplicated, the weight is considered only once.
func WeightOfSigners(signers []common.Address, signingPolicy *policy.SigningPolicy) uint16 {
	currentWeight := uint16(0)
	for i, voter := range signingPolicy.Voters.Voters() {
		if ok := slices.Contains(signers, voter); ok {
			currentWeight += signingPolicy.Voters.VoterWeight(i)
		}
	}

	return currentWeight
}

// DestroyState resets the storage to an uninitialized state.
func (s *Storage) DestroyState() {
	s.active = nil
	s.signingPolicies = make(map[uint32]*policy.SigningPolicy)
	s.activePublicKeys = nil

	s.initialPolicyID = 0
	s.initialPolicyHash = common.Hash{}
}
