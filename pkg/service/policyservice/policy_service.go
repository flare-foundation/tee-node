package policyservice

import (
	"context"
	"encoding/hex"
	"tee-node/pkg/attestation"
	"tee-node/pkg/policy"

	api "tee-node/api/types"

	"github.com/ethereum/go-ethereum/rpc"
)

// Service struct implements the JSON-RPC methods
type Service struct{}

// NewService creates a new policy service
func NewService() *Service {
	return &Service{}
}

// InitializePolicy handles the InitializePolicy request
func (s *Service) InitializePolicy(ctx context.Context, req *api.InitializePolicyRequest) (*api.InitializePolicyResponse, error) {
	select {
	case <-ctx.Done():
		return nil, rpc.ErrClientQuit
	default:
	}

	err := policy.InitializePolicyRequest(req.InitialPolicyBytes, req.NewPolicyRequests)
	if err != nil {
		return nil, err
	}
	return &api.InitializePolicyResponse{}, nil
}

// GetActivePolicy handles the GetActivePolicy request
func (s *Service) GetActivePolicy(ctx context.Context, req *api.GetActivePolicyRequest) (*api.GetActivePolicyResponse, error) {
	select {
	case <-ctx.Done():
		return nil, rpc.ErrClientQuit
	default:
	}

	if policy.ActiveSigningPolicy == nil {
		return nil, rpc.ErrNoResult
	}

	activePolicyBytes, err := policy.EncodeSigningPolicy(policy.ActiveSigningPolicy)
	if err != nil {
		return nil, err
	}

	// Get the attestation token
	nonces := []string{req.Challenge, hex.EncodeToString(activePolicyBytes)}
	var tokenBytes []byte
	tokenBytes, err = attestation.GetGoogleAttestationToken(nonces, attestation.OIDCTokenType)
	if err != nil {
		return nil, err
	}

	return &api.GetActivePolicyResponse{
		ActivePolicy:     activePolicyBytes,
		ActivePolicyHash: hex.EncodeToString(policy.ActiveSigningPolicyHash),
		Token:            string(tokenBytes),
	}, nil
}
