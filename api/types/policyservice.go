package types

type InitializePolicyRequest struct {
	InitialPolicyBytes     []byte
	NewPolicyRequests      []MultiSignedPolicy
	LatestPolicyPublicKeys []ECDSAPublicKey
	Challenge              string
}

type UpdatePolicyAdditionalFixedMessage struct {
	NewPolicyRequest       MultiSignedPolicy
	LatestPolicyPublicKeys []ECDSAPublicKey
}

type MultiSignedPolicy struct {
	PolicyBytes []byte
	Signatures  []*SignatureMessage
}

type InitializePolicyResponse struct {
	Token string
}

type GetActivePolicyRequest struct {
	Challenge string
}

type GetActivePolicyResponse struct {
	ActivePolicy     []byte // The current active policy
	ActivePolicyHash string // The hash of the current active policy
	Token            string
}
