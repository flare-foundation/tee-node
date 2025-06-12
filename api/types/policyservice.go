package types

type InitializePolicyRequest struct {
	InitialPolicyBytes     []byte
	Policies               []MultiSignedPolicy
	LatestPolicyPublicKeys []ECDSAPublicKey
}

type UpdatePolicyRequest struct {
	NewPolicy              MultiSignedPolicy
	LatestPolicyPublicKeys []ECDSAPublicKey
}

type MultiSignedPolicy struct {
	PolicyBytes []byte
	Signatures  []*SignatureMessage
}

type SignatureMessage struct {
	Signature []byte
	PublicKey ECDSAPublicKey
}
