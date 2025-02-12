package types

type GetNodeAttestationTokenRequest struct {
	Nonce string
}

type GetNodeAttestationTokenResponse struct {
	Uuid  string
	Token string
}
