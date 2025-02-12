package types

type InitializePolicyRequest struct {
	InitialPolicyBytes []byte
	NewPolicyRequests  []*SignNewPolicyRequest
}

type SignNewPolicyRequest struct {
	PolicyBytes             []byte // The new policy bytes being proposed/signed
	PolicySignatureMessages []*PolicySignatureMessage
}

type PolicySignatureMessage struct {
	Signature []byte
	PublicKey *ECDSAPublicKey
}

type ECDSAPublicKey struct {
	X string
	Y string
}

type InitializePolicyResponse struct {
}

type SignNewPolicyResponse struct {
	ActivePolicy string // The new active policy (will change if threshold is erached)
}

type GetActivePolicyRequest struct {
}

type GetActivePolicyResponse struct {
	ActivePolicy     []byte // The current active policy
	ActivePolicyHash string // The hash of the current active policy
}
