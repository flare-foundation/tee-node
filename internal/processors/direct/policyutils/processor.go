package policyutils

import (
	"encoding/json"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	commonpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
)

type Processor struct {
	*policy.Storage
}

func NewProcessor(policyStorage *policy.Storage) Processor {
	return Processor{Storage: policyStorage}
}

func (p *Processor) InitializePolicy(i *types.DirectInstruction) ([]byte, error) {
	var err error
	defer func() {
		if err != nil {
			p.DestroyState()
		}
	}()

	var req types.InitializePolicyRequest
	err = json.Unmarshal(i.Message, &req)
	if err != nil {
		return nil, err
	}

	p.Lock()
	defer p.Unlock()

	_, err = p.ActiveSigningPolicy()
	if err == nil {
		return nil, errors.New("policy already initialized")
	}

	initialPolicy, _, err := commonpolicy.FromRawBytes(req.InitialPolicyBytes)
	if err != nil {
		return nil, err
	}

	pubKeysMap, err := processPolicyPublicKeys(req.PublicKeys, initialPolicy)
	if err != nil {
		return nil, err
	}

	err = p.SetInitialPolicy(initialPolicy, pubKeysMap)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (p *Processor) UpdatePolicy(i *types.DirectInstruction) ([]byte, error) {
	var req types.UpdatePolicyRequest
	err := json.Unmarshal(i.Message, &req)
	if err != nil {
		return nil, err
	}

	p.Lock()
	defer p.Unlock()

	newPolicy, err := p.processUpdatePolicyRequest(req.NewPolicy)
	if err != nil {
		return nil, err
	}
	pubKeysMap, err := processPolicyPublicKeys(req.PublicKeys, newPolicy)
	if err != nil {
		return nil, err
	}

	err = p.SetActiveSigningPolicy(newPolicy)
	if err != nil {
		return nil, err
	}
	err = p.SetActiveSigningPolicyPublicKeys(pubKeysMap)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (p *Processor) processUpdatePolicyRequest(signedPolicy types.MultiSignedPolicy) (*commonpolicy.SigningPolicy, error) {
	newPolicy, _, err := commonpolicy.FromRawBytes(signedPolicy.PolicyBytes)
	if err != nil {
		return nil, err
	}

	activePolicy, err := p.ActiveSigningPolicy()
	if err != nil {
		return nil, err
	}
	if newPolicy.RewardEpochID != activePolicy.RewardEpochID+1 {
		return nil, errors.New("policy is not active")
	}

	hash := commonpolicy.Hash(signedPolicy.PolicyBytes)

	signers := make([]common.Address, len(signedPolicy.Signatures))
	for i, sig := range signedPolicy.Signatures {
		signer, err := utils.CheckSignature(hash, sig, activePolicy.Voters.Voters())
		if err != nil {
			return nil, err
		}
		signers[i] = signer
	}

	if policy.WeightOfSigners(signers, activePolicy) <= activePolicy.Threshold {
		return nil, errors.New("threshold for updating policy not reached")
	}

	return newPolicy, nil
}
