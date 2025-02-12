package types

type GetAttestationTokenRequest struct {
	Nonces []string
}

type GetAttestationTokenResponse struct {
	JwtBytes string
}

type GetHardwareAttestationRequest struct {
	Nonce string
}

type GetHardwareAttestationResponse struct {
	JsonAttestation string
}
