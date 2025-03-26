package policyservice

import (
	"encoding/hex"
	"tee-node/pkg/attestation"
	"tee-node/pkg/policy"

	api "tee-node/api/types"

	"github.com/ethereum/go-ethereum/rpc"
)

func InitializePolicy(req *api.InitializePolicyRequest) (*api.InitializePolicyResponse, error) {
	err := policy.InitializePolicyRequest(req.InitialPolicyBytes, req.NewPolicyRequests)
	if err != nil {
		return nil, err
	}
	return &api.InitializePolicyResponse{}, nil
}

// GetActivePolicy handles the GetActivePolicy request
func GetActivePolicy(req *api.GetActivePolicyRequest) (*api.GetActivePolicyResponse, error) {
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
