package types

type NewWalletRequest struct {
	Name      string
	Signature []byte
	Nonce     string
}

type NewWalletResponse struct {
	Finalized bool
	Token     string
}

type PublicKeyRequest struct {
	Name  string
	Nonce string
}

type DeleteWalletRequest struct {
	Name      string
	Signature []byte
	Nonce     string
}

type DeleteWalletResponse struct {
	Finalized bool
	Token     string
}

type PublicKeyResponse struct {
	Address string
	Token   string
}

type SplitWalletRequest struct {
	Name      string
	TeeIds    []string
	Hosts     []string
	Threshold int64
	Signature []byte
	Nonce     string
}

type SplitWalletResponse struct {
	Finalized bool
	Token     string
}

type RecoverWalletRequest struct {
	Name      string
	TeeIds    []string
	Hosts     []string
	ShareIds  []string
	Address   string
	Threshold int64
	Signature []byte
	Nonce     string
}

type RecoverWalletResponse struct {
	Finalized bool
	Token     string
}
