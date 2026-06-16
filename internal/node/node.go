package node

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	csigning "github.com/flare-foundation/go-flare-common/pkg/signing"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/machinepath"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
)

type Node struct {
	teeID      common.Address // The ethereum address of the node, derived from the PrivateKey
	privateKey *ecdsa.PrivateKey
	state      State

	initialOwner common.Address
	extensionID  extensionID
	chainID      uint64 // 0 means unset
	governance   governance

	machinePaths     []machinepath.IMachinePathManagerMachinePath
	machinePathNonce uint64

	lock sync.RWMutex
}

type Info struct {
	TeeID     common.Address // The ethereum address of the node, derived from the PrivateKey
	PublicKey types.PublicKey
	State     State

	InitialOwner         common.Address
	ExtensionID          common.Hash
	ChainID              uint64
	Governance           types.Governance
	MachinePathListNonce uint64
	MachinePathListHash  common.Hash
}

type extensionID struct {
	set   bool
	value common.Hash
}

type governance struct {
	set       bool
	signers   []common.Address
	threshold uint64
	hash      common.Hash
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

		extensionID: extensionID{
			set:   false,
			value: settings.DefaultExtensionID,
		},
		governance: governance{
			set:  false,
			hash: settings.DefaultGovernanceHash,
		},
	}

	err = n.initialOwnerFromEnv()
	if err != nil {
		return nil, err
	}
	err = n.extensionIDFromEnv()
	if err != nil {
		return nil, err
	}
	err = n.chainIDFromEnv()
	if err != nil {
		return nil, err
	}
	err = n.governanceFromEnv()
	if err != nil {
		return nil, err
	}

	logger.Info("Node initialized.")
	return n, nil
}

// State retrieves the current serialized node state.
func (n *Node) State() (types.TeeState, error) {
	return n.state.State()
}

// Info returns the node metadata and current state.
func (n *Node) Info() Info {
	n.lock.RLock()
	defer n.lock.RUnlock()

	signersCopy := append([]common.Address(nil), n.governance.signers...)

	var pathListHash common.Hash
	if n.machinePathNonce != 0 {
		// Errors here would indicate a programming bug in ABI setup,
		// not a runtime condition; fall back to a zero hash and let the
		// signature-verification path surface the mismatch.
		dataHash, err := types.MachinePathListDataHash(n.extensionID.value, n.machinePathNonce, n.machinePaths)
		if err == nil {
			h, err := csigning.NewPayload(csigning.TEEMachinePathList, n.chainID, dataHash).Hash()
			if err == nil {
				pathListHash = h
			}
		}
	}

	return Info{
		TeeID:        n.teeID,
		PublicKey:    types.PubKeyToStruct(&n.privateKey.PublicKey),
		State:        n.state,
		InitialOwner: n.initialOwner,
		ExtensionID:  n.extensionID.value,
		ChainID:      n.chainID,
		Governance: types.Governance{
			Signers:   signersCopy,
			Threshold: n.governance.threshold,
			Hash:      n.governance.hash,
		},
		MachinePathListNonce: n.machinePathNonce,
		MachinePathListHash:  pathListHash,
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
	return utils.Decrypt(cipher, n.privateKey)
}

// SetOwner sets the initial owner of the node. It can only be set once.
func (n *Node) SetOwner(owner common.Address) error {
	n.lock.Lock()
	defer n.lock.Unlock()

	zeroAddress := common.Address{}
	if n.initialOwner != zeroAddress {
		return errors.New("initial owner already set")
	}

	if owner == zeroAddress {
		return errors.New("initial owner cannot be zero address")
	}

	n.initialOwner = owner

	return nil
}

func (n *Node) initialOwnerFromEnv() error {
	n.lock.Lock()
	defer n.lock.Unlock()

	ownerB, isSet, err := bytesFromEnv(settings.InitialOwnerEnvVar)
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

// SetChainID sets the EVM chain ID of the node. It can only be set
// once. The chain ID is bound into the governance-signed payload of
// SET_MACHINE_PATH_LIST.
func (n *Node) SetChainID(chainID uint64) error {
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.chainID != 0 {
		return errors.New("chainID already set")
	}
	if chainID == 0 {
		return errors.New("0 is invalid chainID")
	}
	n.chainID = chainID
	return nil
}

// chainIDFromEnv sets the chain id from the CHAIN_ID environment variable, if present.
func (n *Node) chainIDFromEnv() error {
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.chainID != 0 {
		return errors.New("chainID already set")
	}

	valueStr, exists := syscall.Getenv(settings.ChainIDEnvVar)
	if !exists {
		return nil
	}

	value, err := strconv.ParseUint(strings.TrimSpace(valueStr), 0, 64)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", settings.ChainIDEnvVar, err)
	}
	if value == 0 {
		return errors.New("0 is invalid chainID")
	}

	n.chainID = value
	return nil
}

// ChainID returns the configured EVM chain ID, or an error if it has
// not been set.
func (n *Node) ChainID() (uint64, error) {
	n.lock.RLock()
	defer n.lock.RUnlock()
	if n.chainID == 0 {
		return 0, errors.New("chainID not set")
	}
	return n.chainID, nil
}

// SetExtensionID sets the extension ID of the node. It can only be set once.
func (n *Node) SetExtensionID(id common.Hash) error {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.extensionID.set {
		return errors.New("extension ID already set")
	}

	n.extensionID.set = true
	n.extensionID.value = id

	return nil
}

func (n *Node) extensionIDFromEnv() error {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.extensionID.set {
		return errors.New("extension ID already set")
	}

	extIDB, isSet, err := bytesFromEnv(settings.ExtensionIDEnvVar)
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
	n.extensionID.set = true
	n.extensionID.value = extID

	return nil
}

// SetGovernance sets the governance signer set and threshold. It can only be
// set once. It computes and stores the canonical governance hash.
func (n *Node) SetGovernance(signers []common.Address, threshold uint64) error {
	n.lock.Lock()
	defer n.lock.Unlock()

	return n.setGovernanceLocked(signers, threshold)
}

// setGovernanceLocked is the shared one-shot setter used by SetGovernance and
// governanceFromEnv. The caller must already hold n.lock.
func (n *Node) setGovernanceLocked(signers []common.Address, threshold uint64) error {
	if n.governance.set {
		return errors.New("governance already set")
	}
	if threshold == 0 {
		return errors.New("governance threshold must be at least 1")
	}
	if uint64(len(signers)) < threshold {
		return fmt.Errorf("governance threshold %d exceeds signer count %d", threshold, len(signers))
	}
	zero := common.Address{}
	for i, s := range signers {
		if s == zero {
			return fmt.Errorf("governance signer at index %d is the zero address", i)
		}
	}

	hash, err := types.GovernanceHash(signers, threshold)
	if err != nil {
		return fmt.Errorf("compute governance hash: %w", err)
	}

	n.governance.signers = append([]common.Address(nil), signers...)
	n.governance.threshold = threshold
	n.governance.hash = hash
	n.governance.set = true

	return nil
}

func (n *Node) governanceFromEnv() error {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.governance.set {
		return errors.New("governance already set")
	}

	signersStr, signersSet := syscall.Getenv(settings.GovernanceSignersEnvVar)
	thresholdStr, thresholdSet := syscall.Getenv(settings.GovernanceThresholdEnvVar)
	if !signersSet && !thresholdSet {
		return nil
	}
	if !signersSet || !thresholdSet {
		return fmt.Errorf("governance: both %s and %s must be set together",
			settings.GovernanceSignersEnvVar, settings.GovernanceThresholdEnvVar)
	}

	signers, err := parseSignersList(signersStr)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", settings.GovernanceSignersEnvVar, err)
	}

	threshold, err := strconv.ParseUint(strings.TrimSpace(thresholdStr), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", settings.GovernanceThresholdEnvVar, err)
	}

	return n.setGovernanceLocked(signers, threshold)
}

// parseSignersList parses a comma-separated list of 0x-prefixed Ethereum
// addresses. Whitespace around each entry is trimmed. Empty entries are
// rejected.
func parseSignersList(s string) ([]common.Address, error) {
	parts := strings.Split(s, ",")
	out := make([]common.Address, 0, len(parts))
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("empty signer at index %d", i)
		}
		if !common.IsHexAddress(p) {
			return nil, fmt.Errorf("signer at index %d is not a valid address: %q", i, p)
		}
		out = append(out, common.HexToAddress(p))
	}
	return out, nil
}

// Governance returns the governance signer set, threshold, and whether
// governance has been configured. Signers are returned as a defensive copy.
func (n *Node) Governance() (signers []common.Address, threshold uint64, set bool) {
	n.lock.RLock()
	defer n.lock.RUnlock()

	signersCopy := append([]common.Address(nil), n.governance.signers...)
	return signersCopy, n.governance.threshold, n.governance.set
}

// SetMachinePathList stores the governance-approved list of machine
// paths used to authorize direct-backup operations. The supplied
// nonce must be strictly greater than the currently stored one.
// Path slices are copied defensively.
func (n *Node) SetMachinePathList(paths []machinepath.IMachinePathManagerMachinePath, nonce uint64) error {
	n.lock.Lock()
	defer n.lock.Unlock()

	if nonce <= n.machinePathNonce {
		return fmt.Errorf("machine-path-list nonce %d not higher than current %d", nonce, n.machinePathNonce)
	}

	copied := make([]machinepath.IMachinePathManagerMachinePath, len(paths))
	for i, p := range paths {
		copied[i] = machinepath.IMachinePathManagerMachinePath{
			SourceTeeIds:      append([]common.Address(nil), p.SourceTeeIds...),
			DestinationTeeIds: append([]common.Address(nil), p.DestinationTeeIds...),
		}
	}
	n.machinePaths = copied
	n.machinePathNonce = nonce
	return nil
}

// MachinePaths returns a defensive copy of the governance-approved
// machine paths along with the nonce of the last update.
func (n *Node) MachinePaths() ([]machinepath.IMachinePathManagerMachinePath, uint64) {
	n.lock.RLock()
	defer n.lock.RUnlock()

	out := make([]machinepath.IMachinePathManagerMachinePath, len(n.machinePaths))
	for i, p := range n.machinePaths {
		out[i] = machinepath.IMachinePathManagerMachinePath{
			SourceTeeIds:      append([]common.Address(nil), p.SourceTeeIds...),
			DestinationTeeIds: append([]common.Address(nil), p.DestinationTeeIds...),
		}
	}
	return out, n.machinePathNonce
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
