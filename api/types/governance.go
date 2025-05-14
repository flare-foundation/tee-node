package types

import (
	"encoding/json"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type GovernanceMessage interface {
	Hash() (common.Hash, error)
	GovPolicyHash() common.Hash
}

// ---------------------------
type PauseTeeMessage struct {
	TeeId        common.Address // TODO: probably necessary?
	PausingNonce common.Hash
}

func (message PauseTeeMessage) Hash() (common.Hash, error) {
	messageBytes, err := json.Marshal(message)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(messageBytes), nil
}

// ---------------------------
type ResumeTeeMessage struct {
	GovernanceHash common.Hash
	ResumePairs    []ResumeTeeIdNoncePair
}

type ResumeTeeIdNoncePair struct {
	TeeId        common.Address
	PausingNonce common.Hash
}

func (message ResumeTeeMessage) Hash() (common.Hash, error) {
	messageBytes, err := json.Marshal(message)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(messageBytes), nil
}

func (message ResumeTeeMessage) GovPolicyHash() common.Hash {
	return message.GovernanceHash
}

// ---------------------------
type PausingAddressSetMessage struct {
	GovernanceHash         common.Hash
	PausingAddressSettings []PausingAddressSettings
}

type PausingAddressSettings struct {
	PauserAddressSetupNonce big.Int
	TeeId                   common.Address
	PausingAddresses        []common.Address
}

func (message PausingAddressSetMessage) Hash() (common.Hash, error) {
	messageBytes, err := json.Marshal(message)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(messageBytes), nil
}

func (message PausingAddressSetMessage) GovPolicyHash() common.Hash {
	return message.GovernanceHash
}

// ---------------------------
type UpgradePathMessage struct {
	GovernanceHash common.Hash
	UpgradePaths   []UpgradePath
}

type UpgradePath struct {
	InitialSet []CodeVersion
	TargetSet  []CodeVersion
}

type CodeVersion struct {
	Platform string
	CodeHash common.Hash
}

// Todo: implement this instead keccak256(abi.encode(TeeNodeVersion(_sourceCodeHash, _sourcePlatform)));
func (version CodeVersion) Hash() (common.Hash, error) {
	messageBytes, err := json.Marshal(version)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(messageBytes), nil
}

func (message UpgradePathMessage) Hash() (common.Hash, error) {
	messageBytes, err := json.Marshal(message)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(messageBytes), nil
}

func (message UpgradePathMessage) GovPolicyHash() common.Hash {
	return message.GovernanceHash
}

// ---------------------------
type BanVersionMessage struct {
	GovernanceHash common.Hash
	CodeVersions   []CodeVersion
}

func (message BanVersionMessage) Hash() (common.Hash, error) {
	messageBytes, err := json.Marshal(message)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(messageBytes), nil
}

func (message BanVersionMessage) GovPolicyHash() common.Hash {
	return message.GovernanceHash
}

// ------------------------------

type GovernancePolicy struct {
	Signers   []common.Address
	Threshold uint8
}

func (gp *GovernancePolicy) Hash() (common.Hash, error) {
	messageBytes, err := json.Marshal(gp)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(messageBytes), nil
}
