package policyservice

import (
	"context"
	"tee-node/internal/policy"

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

	err := policy.InitializePolicyInternal(req)
	if err != nil {
		return nil, err
	}
	return &api.InitializePolicyResponse{}, nil
}

// SignNewPolicy handles the SignNewPolicy request
func (s *Service) SignNewPolicy(ctx context.Context, req *api.SignNewPolicyRequest) (*api.SignNewPolicyResponse, error) {
	select {
	case <-ctx.Done():
		return nil, rpc.ErrClientQuit
	default:
	}

	err := policy.SignNewPolicyInternal(req)
	if err != nil {
		return nil, err
	}

	return &api.SignNewPolicyResponse{
		ActivePolicy: policy.EncodeToHex(policy.ActiveSigningPolicyHash),
	}, nil
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

	return &api.GetActivePolicyResponse{
		ActivePolicy:     activePolicyBytes,
		ActivePolicyHash: policy.EncodeToHex(policy.ActiveSigningPolicyHash),
	}, nil
}
