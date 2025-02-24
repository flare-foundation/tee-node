package attestationservice

import (
	"context"
	"fmt"

	// Import your generated proto package

	api "tee-node/api/types"
	"tee-node/internal/attestation"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service struct {
}

// NewService creates a new signing service
func NewService() *Service {
	return &Service{}
}

// TODO: req should not have
func (s *Service) GetAttestationToken(ctx context.Context, req *api.GetAttestationTokenRequest) (*api.GetAttestationTokenResponse, error) {
	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request cancelled")
	default:
	}

	tokenbytes, err := attestation.GetGoogleAttestationToken(req.Nonces, attestation.OIDCTokenType)
	if err != nil {
		return nil, err
	}

	return &api.GetAttestationTokenResponse{
		JwtBytes: string(tokenbytes),
	}, nil
}

func (s *Service) GetHardwareAttestation(ctx context.Context, req *api.GetHardwareAttestationRequest) (*api.GetHardwareAttestationResponse, error) {
	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request cancelled")
	default:
	}

	nonce := []byte(req.Nonce)
	if len(nonce) != 32 {
		return nil, fmt.Errorf("nonce length must be exactly 32 bytes, got %d", len(nonce))
	}

	att, err := attestation.CreateAttestation(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation: %w", err)
	}

	json_attestation, err := attestation.EncodeAttestationJSON(att)
	if err != nil {
		return nil, fmt.Errorf("failed to encode attestation: %w", err)
	}

	return &api.GetHardwareAttestationResponse{
		JsonAttestation: json_attestation,
	}, nil
}
