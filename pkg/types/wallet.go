package types

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// KeyInfo identifies a wallet key together with its current replay-protection nonce.
type KeyInfo struct {
	WalletID common.Hash `json:"walletId"`
	KeyID    uint64      `json:"keyId"`
	Nonce    uint64      `json:"nonce"`
}

// SignedKeyDirectBackup is the envelope produced by KEY_DIRECT_BACKUP.
// Payload is a JSON-encoded KeyDirectBackupPayload; TEESignature is the
// source TEE's signature over
// signing.Payload{TEEKeyDirectBackupTag, chainID, keccak256(Payload)}.Hash().
type SignedKeyDirectBackup struct {
	Payload      hexutil.Bytes `json:"payload"`
	TEESignature hexutil.Bytes `json:"teeSignature"`
}
