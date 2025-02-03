package nodeservice

import (
	"context"
	"tee-node/config"
	nd "tee-node/gen/go/node/v1"
	"tee-node/internal/attestation"
	"tee-node/internal/node"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Service implements the generated SigningServiceServer interface
type Service struct {
	// Embed the generated UnimplementedSigningServiceServer
	nd.UnimplementedNodeServiceServer
	// Add any dependencies your service needs
}

// NewService creates a new signing service
func NewService() *Service {
	return &Service{}
}

func (s *Service) GetNodeAttestationToken(ctx context.Context, req *nd.GetNodeAttestationTokenRequest) (*nd.GetNodeAttestationTokenResponse, error) {
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

	return &nd.GetNodeAttestationTokenResponse{
		Uuid:  nodeId.Uuid,
		Token: string(tokenBytes),
	}, nil
}
