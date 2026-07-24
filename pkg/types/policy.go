package types

type InitializePolicyRequest struct {
	InitialPolicyBytes []byte
	PublicKeys         []PublicKey
}

type UpdatePolicyRequest struct {
	NewPolicy  MultiSignedPolicy
	PublicKeys []PublicKey
}

type MultiSignedPolicy struct {
	PolicyBytes []byte
	Signatures  [][]byte
}
