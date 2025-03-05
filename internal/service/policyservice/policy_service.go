package policyservice

import (
	"context"
	"encoding/hex"
	"tee-node/internal/attestation"
	"tee-node/internal/policy"
	"tee-node/internal/requests"

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

	err := InitializePolicyInternal(req)
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

	signPolicyRequest := policy.NewSignPaymentRequest(req.PolicyBytes)

	requestCounter, thresholdReached, err := requests.ProcessRequest(signPolicyRequest, req.Signature.Signature)
	if err != nil {
		return nil, err
	}

	if thresholdReached && !requestCounter.Done {
		err = policy.SetNewPolicyInternal(req)
		if err != nil {
			return nil, err
		}

		requestCounter.Done = true
	}

	// Get the attestation token
	nonces := []string{req.Challenge, requestCounter.Request.Identifier()}
	tokenBytes, err := attestation.GetGoogleAttestationToken(nonces, attestation.OIDCTokenType)
	if err != nil {
		return nil, err
	}

	return &api.SignNewPolicyResponse{
		ActivePolicy:     hex.EncodeToString(policy.ActiveSigningPolicyHash),
		ThresholdReached: thresholdReached,
		Token:            string(tokenBytes),
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
