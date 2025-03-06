package nodeservice

import (
	"context"
	"encoding/hex"
	api "tee-node/api/types"
	"tee-node/internal/attestation"
	"tee-node/internal/node"
	"tee-node/internal/policy"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service struct {
}

// NewService creates a new signing service
func NewService() *Service {
	return &Service{}
}

func (s *Service) GetNodeInfo(ctx context.Context, req *api.GetNodeInfoRequest) (*api.GetNodeInfoResponse, error) {
	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request cancelled")
	default:
	}

	nodeId := node.GetNodeId()

	responseData := api.GetNodeInfoData{
		Id:                  nodeId.Id,
		Status:              nodeId.Status,
		EncryptionPublicKey: hex.EncodeToString(nodeId.EncryptionKey.PublicKey[:]),
		SigningPublicKey: api.ECDSAPublicKey{
			X: nodeId.SignatureKey.PublicKey.X.Text(16),
			Y: nodeId.SignatureKey.PublicKey.Y.Text(16),
		},
		SigningPolicyHash: hex.EncodeToString(policy.ActiveSigningPolicyHash),
	}

	hash, err := responseData.Hash()
	if err != nil {
		return nil, err
	}
	nonces := []string{req.Nonce, "GetNodeInfo", hash}
	var tokenBytes []byte
	tokenBytes, err = attestation.GetGoogleAttestationToken(nonces, attestation.PKITokenType)
	if err != nil {
		return nil, err
	}

	return &api.GetNodeInfoResponse{Data: responseData, Token: string(tokenBytes)}, nil
}
