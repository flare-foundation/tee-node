package types

import "github.com/flare-foundation/go-flare-common/pkg/tee/structs/tee"

type InitializePolicyRequest struct {
	InitialPolicyBytes []byte
	PublicKeys         []tee.PublicKey
}

type UpdatePolicyRequest struct {
	NewPolicy  MultiSignedPolicy
	PublicKeys []tee.PublicKey
}

type MultiSignedPolicy struct {
	PolicyBytes []byte
	Signatures  [][]byte
}
