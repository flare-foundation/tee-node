package nodeservice

import (
	"encoding/hex"
	api "tee-node/api/types"
	"tee-node/pkg/attestation"
	"tee-node/pkg/node"
	"tee-node/pkg/policy"
)

func GetNodeInfo(req *api.GetNodeInfoRequest) (*api.GetNodeInfoResponse, error) {
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
