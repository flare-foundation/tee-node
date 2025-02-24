package wallets

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"tee-node/internal/node"
)

type NewWalletRequest struct {
	Name string
}

func NewNewWalletRequest(name string) NewWalletRequest {
	return NewWalletRequest{Name: name}
}

func (w NewWalletRequest) Message() string {
	return fmt.Sprintf("NewWalletRequest(%s)", w.Name)
}

func (w NewWalletRequest) Check() error {
	return nil
}

type DeleteWalletRequest struct {
	Name string
}

func NewDeleteWalletRequest(name string) DeleteWalletRequest {
	return DeleteWalletRequest{Name: name}
}

func (w DeleteWalletRequest) Message() string {
	return fmt.Sprintf("DeleteWalletRequest(%s)", w.Name)
}

func (w DeleteWalletRequest) Check() error {
	return nil
}

type SplitWalletRequest struct {
	Name       string
	IDs        []string
	Hosts      []string
	PublicKeys []string
	NumShares  int
	Threshold  int
}

func NewSplitWalletRequest(name string, ids, hosts, publicKeys []string, threshold int) (SplitWalletRequest, error) {
	if len(ids) != len(hosts) {
		return SplitWalletRequest{}, errors.New("length of IDs and hosts do not match")
	}
	if len(ids) < threshold || threshold < 1 {
		return SplitWalletRequest{}, errors.New("threshold error")
	}

	return SplitWalletRequest{Name: name, IDs: ids, Hosts: hosts, PublicKeys: publicKeys, NumShares: len(ids), Threshold: threshold}, nil
}

func (w SplitWalletRequest) Message() string {
	data, _ := json.Marshal(w)
	return fmt.Sprintf("SplitWalletRequest(%s)", string(data))
}

func (w SplitWalletRequest) Check() error {
	return nil
}

type RecoverWalletRequest struct {
	Name      string
	IDs       []string
	Hosts     []string
	ShareIds  []string
	PubKey    string
	NumShares int
}

func NewRecoverWalletRequest(name string, ids, hosts, shareIds []string, pubKey string) (RecoverWalletRequest, error) {
	if len(ids) != len(hosts) || len(ids) != len(shareIds) {
		fmt.Printf("len(ids): %d, len(hosts): %d, len(shareIds): %d\n", len(ids), len(hosts), len(shareIds))
		return RecoverWalletRequest{}, errors.New("length of tees' IDs, hosts and shares' ids do not match")
	}

	return RecoverWalletRequest{Name: name, IDs: ids, Hosts: hosts, PubKey: pubKey, ShareIds: shareIds, NumShares: len(ids)}, nil
}

func (w RecoverWalletRequest) Message() string {
	data, _ := json.Marshal(w)
	return fmt.Sprintf("SplitWalletRequest(%s)", string(data))
}

func (w RecoverWalletRequest) Check() error {
	myNode := node.GetNodeId()
	if hex.EncodeToString(myNode.EncryptionKey.PublicKey[:]) != w.PubKey {
		return errors.New("public key not matching node's public key")
	}

	return nil
}

// Todo when ripple transactions ready
type TransactionRequest struct {
	From       string
	To         string
	Nonce      string
	Signatures []string
}

func NewTransactionRequest(from, to string) TransactionRequest {
	return TransactionRequest{From: from, To: to}
}

func (w TransactionRequest) Message() string {
	return fmt.Sprintf("NewTransactionRequest(%s, %s, %s)", w.From, w.To, w.Nonce)
}
