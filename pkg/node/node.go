package node

import (
	"crypto/ecdsa"
	"tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/crypto"
)

var nodeId = NodeId{}

const (
	operationalStatus     = "operational"
	pausedForUpdateStatus = "paused_for_update"
)

type NodeId struct {
	Id            string
	Status        string
	EncryptionKey utils.EncryptionKey
	SignatureKey  *ecdsa.PrivateKey
}

func InitNode() error {
	var err error
	nodeId.SignatureKey, err = utils.GenerateEthereumPrivateKey()
	if err != nil {
		return err
	}

	address := crypto.PubkeyToAddress(nodeId.SignatureKey.PublicKey)
	nodeId.Id = address.Hex()

	nodeId.EncryptionKey, err = utils.GenerateEncryptionKeyPair()
	if err != nil {
		return err
	}

	nodeId.Status = operationalStatus

	return nil
}

func GetNodeId() NodeId {
	return nodeId
}
