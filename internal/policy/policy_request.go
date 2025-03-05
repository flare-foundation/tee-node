package policy

import (
	"encoding/hex"
	"fmt"
	"tee-node/api/types"
)

type SignPolicyRequest struct {
	PolicyBytes []byte
}

func NewSignPaymentRequest(PolicyBytes []byte) SignPolicyRequest {
	return SignPolicyRequest{
		PolicyBytes: PolicyBytes,
	}
}

func (sp SignPolicyRequest) Identifier() string {
	return fmt.Sprintf("SignPaymentRequest(%s)", hex.EncodeToString(sp.PolicyBytes))
}
func (sp SignPolicyRequest) Hash() []byte {
	return SigningPolicyHash(sp.PolicyBytes)
}

func (sp SignPolicyRequest) RequestType() types.RequestType {
	return types.SignPolicyRequest
}

func (sp SignPolicyRequest) RewardEpochId() uint32 {
	policy, err := DecodeSigningPolicy(sp.PolicyBytes)
	if err != nil {
		return 0
	}

	return policy.RewardEpochId - 1
}
