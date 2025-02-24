package types

type NewWalletRequest struct {
	Name      string
	Signature []byte
	Nonce     string // Note: Challenge?
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
	Nonce     string // Note: Challenge?
}

type DeleteWalletResponse struct {
	Finalized bool
	Token     string
}

type PublicKeyResponse struct {
	PublicKey  ECDSAPublicKey
	EthAddress string
	Token      string
}

// Note: I know this isn't the best, but we need to discuss the APIs we want
type MultisigAccountInfoResponse struct {
	PublicKey  string // SEC1 encoded public key
	XrpAddress string
	Token      string
}

type SplitWalletRequest struct {
	Name       string
	TeeIds     []string
	Hosts      []string
	PublicKeys []string
	Threshold  int64
	Signature  []byte
	Nonce      string // Note: Challenge?
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
	PublicKey string
	Address   string
	Threshold int64
	Signature []byte
	Nonce     string // Note: Challenge?
}

type RecoverWalletResponse struct {
	Finalized bool
	Token     string
}
