package policyutils

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	commonpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	csigning "github.com/flare-foundation/go-flare-common/pkg/signing"
	pnode "github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
)

type Processor struct {
	*policy.Storage
	node *pnode.Node
}

// NewProcessor returns a policy utility processor backed by the provided
// storage and node.
func NewProcessor(teeNode *pnode.Node, policyStorage *policy.Storage) Processor {
	return Processor{Storage: policyStorage, node: teeNode}
}

// InitializePolicy sets the first signing policy along with its associated
// public keys.
func (p *Processor) InitializePolicy(ctx context.Context, i *types.DirectInstruction) ([]byte, error) {
	var req types.InitializePolicyRequest
	if err := json.Unmarshal(i.Message, &req); err != nil {
		return nil, err
	}

	p.Lock()
	defer p.Unlock()

	if _, err := p.ActiveSigningPolicy(); err == nil {
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

	// timeout check before changing state
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := p.SetInitialPolicy(initialPolicy, pubKeysMap); err != nil {
		p.DestroyState()
		return nil, err
	}

	return nil, nil
}

// UpdatePolicy validates and applies the next signing policy from a
// multisigned submission.
func (p *Processor) UpdatePolicy(ctx context.Context, i *types.DirectInstruction) ([]byte, error) {
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

	// timeout check before changing state
	if err := ctx.Err(); err != nil {
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

// SetMachinePathList stores the governance-approved list of machine
// paths used to authorize direct-backup operations. It requires enough
// valid governance signatures over the canonical
// (chainID, extensionID, paths, nonce) hash to meet the configured
// threshold and a nonce strictly higher than the one currently stored.
// Per-operation authorization is enforced by the wallet handlers.
func (p *Processor) SetMachinePathList(ctx context.Context, i *types.DirectInstruction) ([]byte, error) {
	var req types.SetMachinePathListRequest
	if err := json.Unmarshal(i.Message, &req); err != nil {
		return nil, err
	}

	if err := verifyGovernanceSignatures(p.node, req); err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := p.node.SetMachinePathList(req.Paths, req.Nonce); err != nil {
		return nil, err
	}

	return nil, nil
}

// verifyGovernanceSignatures recovers the signers of req.Signatures over
// the canonical machine-path-list message hash and requires at least
// the configured threshold of distinct addresses from the node's
// governance signer set.
func verifyGovernanceSignatures(n *pnode.Node, req types.SetMachinePathListRequest) error {
	govSigners, threshold, set := n.Governance()
	if !set {
		return errors.New("governance not configured")
	}
	chainID, err := n.ChainID()
	if err != nil {
		return err
	}
	extensionID := n.Info().ExtensionID

	dataHash, hashErr := types.MachinePathListDataHash(extensionID, req.Nonce, req.Paths)
	if hashErr != nil {
		return hashErr
	}
	hash, hashErr := csigning.NewPayload(csigning.TEEMachinePathList, chainID, dataHash).Hash()
	if hashErr != nil {
		return hashErr
	}

	seen := make(map[common.Address]struct{}, len(req.Signatures))
	for _, sig := range req.Signatures {
		signer, err := utils.CheckSignature(hash[:], sig, govSigners)
		if err != nil {
			return err
		}
		seen[signer] = struct{}{}
	}

	if uint64(len(seen)) < threshold {
		return fmt.Errorf("governance threshold not reached: %d unique signer(s), need %d", len(seen), threshold)
	}
	return nil
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
