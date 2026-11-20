package types

type InitializePolicyRequest struct {
	InitialPolicyBytes []byte      `json:"initialPolicyBytes"`
	PublicKeys         []PublicKey `json:"publicKeys"`
}

type UpdatePolicyRequest struct {
	NewPolicy  MultiSignedPolicy `json:"newPolicy"`
	PublicKeys []PublicKey       `json:"publicKeys"`
}

type MultiSignedPolicy struct {
	PolicyBytes []byte   `json:"policyBytes"`
	Signatures  [][]byte `json:"signatures"`
}
