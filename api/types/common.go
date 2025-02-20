package types

type SignatureMessage struct {
	Signature []byte
	PublicKey *ECDSAPublicKey
}

type ECDSAPublicKey struct {
	X string
	Y string
}

type ResponseMessage struct {
	Message          string
	ThresholdReached bool
	Token            string // Google OIDC token (Attestation token)
}
