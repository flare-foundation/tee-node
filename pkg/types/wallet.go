package types

import "github.com/ethereum/go-ethereum/common"

// KeyInfo identifies a wallet key together with its current replay-protection nonce.
type KeyInfo struct {
	WalletID common.Hash `json:"walletId"`
	KeyID    uint64      `json:"keyId"`
	Nonce    uint64      `json:"nonce"`
}
