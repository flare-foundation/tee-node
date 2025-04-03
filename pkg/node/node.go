package node

import (
	"crypto/ecdsa"
	"tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var nodeId = NodeId{}

const (
	operationalStatus     = "operational"
	pausedForUpdateStatus = "paused_for_update"
)

type NodeId struct {
	Id            common.Address // The ethereum address of the node, derived from the SignatureKey
	Status        string
	EncryptionKey utils.EncryptionKey // used for encrypted communication between TEE nodes over websocket
	SignatureKey  *ecdsa.PrivateKey   //todo: will be used for the TLS certificate I think?
}

func InitNode() error {
	var err error
	nodeId.SignatureKey, err = utils.GenerateEthereumPrivateKey()
	if err != nil {
		return err
	}

	address := crypto.PubkeyToAddress(nodeId.SignatureKey.PublicKey)
	nodeId.Id = address

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
