package node

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
)

const (
	initialOwnerEnvVar = "INITIAL_OWNER"
	extensionIDEnvVar  = "EXTENSION_ID"
)

type Node struct {
	teeID      common.Address // The ethereum address of the node, derived from the PrivateKey
	privateKey *ecdsa.PrivateKey
	state      State

	initialOwner common.Address
	extensionID  common.Hash

	lock sync.RWMutex
}

type Info struct {
	TeeID     common.Address // The ethereum address of the node, derived from the PrivateKey
	PublicKey types.PublicKey
	State     State

	InitialOwner common.Address
	ExtensionID  common.Hash
}

type State interface {
	// State encodes the node state into its serialized representation.
	State() (types.TeeState, error)
}

type ZeroState struct{}

// State returns the zero-value node state.
func (ZeroState) State() (types.TeeState, error) {
	return types.TeeState{
		SystemState:        hexutil.Bytes{},
		SystemStateVersion: common.Hash{},
		State:              hexutil.Bytes{},
		StateVersion:       common.Hash{},
	}, nil
}

// Initialize generates node's private key and sets the teeID.
func Initialize(state State) (*Node, error) {
	var privKey, err = crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	id := crypto.PubkeyToAddress(privKey.PublicKey)

	n := &Node{
		teeID:      id,
		privateKey: privKey,
		state:      state,
	}

	err = n.initialOwnerFromEnv()
	if err != nil {
		return nil, err
	}
	err = n.extensionIDFromEnv()
	if err != nil {
		return nil, err
	}

	return n, nil
}

// State retrieves the current serialized node state.
func (n *Node) State() (types.TeeState, error) {
	return n.state.State()
}

// Info returns the node metadata and current state.
func (n *Node) Info() Info {
	return Info{
		TeeID:        n.teeID,
		PublicKey:    types.PubKeyToStruct(&n.privateKey.PublicKey),
		State:        n.state,
		InitialOwner: n.initialOwner,
		ExtensionID:  n.extensionID,
	}
}

// TeeID is the ethereum address corresponding to the node's private key.
func (n *Node) TeeID() common.Address {
	return n.teeID
}

// Sign signs the hash with the node's private key.
func (n *Node) Sign(msgHash []byte) ([]byte, error) {
	return utils.Sign(msgHash, n.privateKey)
}

// Decrypt decrypts the ciphertext with the node's private key.
func (n *Node) Decrypt(cipher []byte) ([]byte, error) {
	privKeyDecryption, err := utils.ECDSAPrivKeyToECIES(n.privateKey)
	if err != nil {
		return nil, err
	}

	plaintext, err := privKeyDecryption.Decrypt(cipher, nil, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// SetOwner sets the initial owner of the node. It can only be set once.
func (n *Node) SetOwner(owner common.Address) error {
	n.lock.Lock()
	defer n.lock.Unlock()

	zeroAddress := common.Address{}
	if n.initialOwner != zeroAddress {
		return errors.New("initial owner already set")
	}

	n.initialOwner = owner

	return nil
}

func (n *Node) initialOwnerFromEnv() error {
	n.lock.Lock()
	defer n.lock.Unlock()

	ownerB, isSet, err := bytesFromEnv(initialOwnerEnvVar)
	if !isSet {
		return nil
	}
	if err != nil {
		return fmt.Errorf("invalid owner address: %w", err)
	}
	if len(ownerB) != 20 {
		return fmt.Errorf("invalid owner address: wrong length %d", len(ownerB))
	}

	ownerAddr := common.BytesToAddress(ownerB)
	n.initialOwner = ownerAddr
	return nil
}

// SetExtensionID sets the extension ID of the node. It can only be set once.
func (n *Node) SetExtensionID(id common.Hash) error {
	n.lock.Lock()
	defer n.lock.Unlock()

	zeroHash := common.Hash{}
	if n.extensionID != zeroHash {
		return errors.New("extension id already set")
	}

	n.extensionID = id

	return nil
}

func (n *Node) extensionIDFromEnv() error {
	n.lock.Lock()
	defer n.lock.Unlock()

	extIDB, isSet, err := bytesFromEnv(extensionIDEnvVar)
	if !isSet {
		return nil
	}
	if err != nil {
		return fmt.Errorf("invalid extension ID: %w", err)
	}
	if len(extIDB) != 32 {
		return fmt.Errorf("invalid extension ID: wrong length %d", len(extIDB))
	}

	extID := common.BytesToHash(extIDB)
	n.extensionID = extID
	return nil
}

func bytesFromEnv(varName string) ([]byte, bool, error) {
	valueStr, exists := syscall.Getenv(varName)
	if !exists {
		return nil, false, fmt.Errorf("environment variable %s not set", varName)
	}

	valueStr, _ = strings.CutPrefix(valueStr, "0x")
	valueStr, _ = strings.CutPrefix(valueStr, "0X")

	valueB, err := hex.DecodeString(valueStr)
	if err != nil {
		return nil, true, fmt.Errorf("invalid hex in environment variable %s: %w", varName, err)
	}

	return valueB, true, nil
}
