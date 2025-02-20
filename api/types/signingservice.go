package types

type SignPaymentTransactionRequest struct {
	WalletName  string
	PaymentHash string
	Signature   []byte
	Challenge   string
}

type GetPaymentSignatureRequest struct {
	WalletName  string
	PaymentHash string
	Challenge   string
}

type GetPaymentSignatureResponse struct {
	TxnSignature  []byte
	SigningPubKey []byte
	Account       string
	Token         string // Google OIDC token (Attestation token)
}
