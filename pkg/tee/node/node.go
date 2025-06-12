package node

import (
	"crypto/ecdsa"
	"tee-node/api/types"
	"tee-node/pkg/tee/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

var node = Node{}

const (
	operationalStatus     = "operational"
	pausedForUpdateStatus = "paused_for_update"
)

type Node struct {
	TeeId      common.Address // The ethereum address of the node, derived from the PrivateKey
	Status     string
	PrivateKey *ecdsa.PrivateKey
}

type NodeInfo struct {
	TeeId     common.Address // The ethereum address of the node, derived from the PrivateKey
	Status    string
	PublicKey types.ECDSAPublicKey
}

func InitNode() error {
	var err error
	node.PrivateKey, err = utils.GenerateEthereumPrivateKey()
	if err != nil {
		return err
	}

	address := crypto.PubkeyToAddress(node.PrivateKey.PublicKey)
	node.TeeId = address

	node.Status = operationalStatus

	return nil
}

func GetNodeInfo() NodeInfo {
	return NodeInfo{TeeId: node.TeeId, Status: node.Status, PublicKey: types.PubKeyToStruct(&node.PrivateKey.PublicKey)}
}

func GetTeeId() common.Address {
	return node.TeeId
}

func Sign(msgHash []byte) ([]byte, error) {
	return utils.Sign(msgHash, node.PrivateKey)
}

func Decrypt(cipher []byte) ([]byte, error) {
	privKeyDecryption := ecies.ImportECDSA(node.PrivateKey)
	plaintext, err := privKeyDecryption.Decrypt(cipher, nil, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
