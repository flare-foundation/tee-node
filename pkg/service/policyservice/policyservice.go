package policyservice

import (
	"encoding/hex"

	"github.com/pkg/errors"

	api "tee-node/api/types"
	"tee-node/pkg/attestation"
	"tee-node/pkg/policy"
)

func GetActivePolicy(req *api.GetActivePolicyRequest) (*api.GetActivePolicyResponse, error) {
	activeSigningPolicy := policy.GetActiveSigningPolicy()
	if activeSigningPolicy == nil {
		return nil, errors.New("no active policy")
	}
	activePolicyBytes, err := policy.EncodeSigningPolicy(activeSigningPolicy)
	if err != nil {
		return nil, err
	}
	activePolicyHash := policy.SigningPolicyBytesToHash(activePolicyBytes)

	// Get the attestation token
	nonces := []string{req.Challenge}
	var tokenBytes []byte
	tokenBytes, err = attestation.GetGoogleAttestationToken(nonces, attestation.OIDCTokenType)
	if err != nil {
		return nil, err
	}

	return &api.GetActivePolicyResponse{
		ActivePolicy:     activePolicyBytes,
		ActivePolicyHash: hex.EncodeToString(activePolicyHash),
		Token:            string(tokenBytes),
	}, nil
}
