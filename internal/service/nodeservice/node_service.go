package nodeservice

import (
	"context"
	api "tee-node/api/types"
	"tee-node/config"
	"tee-node/internal/attestation"
	"tee-node/internal/node"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service struct {
}

// NewService creates a new signing service
func NewService() *Service {
	return &Service{}
}

func (s *Service) GetNodeAttestationToken(ctx context.Context, req *api.GetNodeAttestationTokenRequest) (*api.GetNodeAttestationTokenResponse, error) {
	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request cancelled")
	default:
	}

	nodeId := node.GetNodeId()
	nonces := []string{req.Nonce, "GetNodeAttestationToken"}

	var tokenBytes []byte
	var err error
	if config.Mode == 0 {
		tokenBytes, err = attestation.GetGoogleAttestationToken(nonces)
		if err != nil {
			return nil, err
		}
	}

	return &api.GetNodeAttestationTokenResponse{
		Uuid:  nodeId.Uuid,
		Token: string(tokenBytes),
	}, nil
}
