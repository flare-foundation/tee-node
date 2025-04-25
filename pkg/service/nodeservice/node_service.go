package nodeservice

import (
	"encoding/hex"
	api "tee-node/api/types"
	"tee-node/pkg/attestation"
	"tee-node/pkg/node"
	"tee-node/pkg/policy"
)

func GetNodeInfo(req *api.GetNodeInfoRequest) (*api.GetNodeInfoResponse, error) {
	nodeInfo := node.GetNodeInfo()
	activePolicy := policy.GetActiveSigningPolicy()
	activePolicyHash, err := policy.SigningPolicyToHash(activePolicy)
	if err != nil {
		return nil, err
	}

	responseData := api.GetNodeInfoData{
		TeeId:             nodeInfo.TeeId,
		Status:            nodeInfo.Status,
		PublicKey:         nodeInfo.PublicKey,
		SigningPolicyHash: hex.EncodeToString(activePolicyHash),
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
