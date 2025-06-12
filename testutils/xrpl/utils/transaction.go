package utils

import (
	"encoding/hex"
	"fmt"
)

// Todo: We need to decide exactly which fields we need, the rest we will remove
type TxBase struct {
	TransactionType    TransactionType
	Flags              *TransactionFlag `json:",omitempty"`
	SourceTag          *uint32          `json:",omitempty"`
	Account            Account
	Sequence           uint32
	Fee                Value
	AccountTxnID       *Hash256        `json:",omitempty"`
	SigningPubKey      *PublicKey      `json:",omitempty"`
	TxnSignature       []byte `json:",omitempty"`
	Signers            []Signer        `json:",omitempty"`
	Memos              Memos           `json:",omitempty"`
	PreviousTxnID      *Hash256        `json:",omitempty"`
	LastLedgerSequence *uint32         `json:",omitempty"`
	Hash               Hash256         `json:"hash"`
}

type SignerItem struct {
	Account       Account
	TxnSignature  []byte `json:",omitempty"`
	SigningPubKey *PublicKey      `json:",omitempty"`
}

type Signer struct {
	Signer SignerItem
}

type Payment struct {
	TxBase
	Destination    Account
	Amount         Amount
	SendMax        *Amount  `json:",omitempty"`
	DeliverMin     *Amount  `json:",omitempty"`
	Paths          *PathSet `json:",omitempty"`
	DestinationTag *uint32  `json:",omitempty"`
	InvoiceID      *Hash256 `json:",omitempty"`
	TicketSequence *uint32  `json:",omitempty"`
}

func (s *SignerItem) String() string {
	accAddress := s.SigningPubKey.Address()
	txnSignature := hex.EncodeToString(s.TxnSignature)
	pubKey := hex.EncodeToString(s.SigningPubKey.Bytes())

	return fmt.Sprintf("Account: %v, TxnSignature: %v, PubKey: %v\n", accAddress, txnSignature, pubKey)
}
