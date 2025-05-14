package node

import (
	"math/big"
	mathrand "math/rand"
	"slices"
	"sync"
	"tee-node/api/types"
	"tee-node/pkg/config"
	"tee-node/pkg/utils"
	"time"

	"github.com/pkg/errors"

	api "tee-node/api/types"

	"github.com/ethereum/go-ethereum/common"
)

var governancePolicy *api.GovernancePolicy
var codeVersionStorage *CodeVersionStorage

var PausingAddressesStorage *PausingAddressStorage
var PausingNoncesStorage *PausingNonceStorage

var DefaultWalletPausingNonce = GeneratePausingNonce()

func init() {
	governancePolicy = InitGovernancePolicy()
	codeVersionStorage = InitCodeVersionStorage()

	PausingAddressesStorage = InitPausingAddressesStorage()
	PausingNoncesStorage = InitPausingNonceStorage()
}

type CodeVersionStorage struct {
	SelfVersion           types.CodeVersion
	ValidUpdgradeVersions []types.CodeVersion  // Code versions this TEE can upgrade to
	BannedVersions        map[common.Hash]bool // codeVersionHash -> isBanned

	sync.RWMutex
}

type PausingAddressStorage struct {
	TeePauserAddresses         []common.Address
	TeePauserAddressSetupNonce big.Int

	sync.RWMutex
}

type PausingNonceStorage struct {
	TeePausingNonce common.Hash
	IsTeePaused     bool

	sync.RWMutex
}

func InitGovernancePolicy() *api.GovernancePolicy {
	return &api.GovernancePolicy{
		Signers:   config.GovernanceSigners,
		Threshold: config.GovernanceThreshold,
	}
}

func InitCodeVersionStorage() *CodeVersionStorage {
	return &CodeVersionStorage{
		ValidUpdgradeVersions: []types.CodeVersion{},
		BannedVersions:        make(map[common.Hash]bool),
	}
}

func InitPausingAddressesStorage() *PausingAddressStorage {
	return &PausingAddressStorage{
		TeePauserAddresses:         []common.Address{},
		TeePauserAddressSetupNonce: big.Int{},
	}
}

func InitPausingNonceStorage() *PausingNonceStorage {
	return &PausingNonceStorage{
		TeePausingNonce: GeneratePausingNonce(),
		IsTeePaused:     false,
	}
}

func NewGovernance(signers []common.Address, threshold uint8, version string) *api.GovernancePolicy {
	return &api.GovernancePolicy{
		Signers:   signers,
		Threshold: threshold,
	}
}

func GetGovernancePolicy() *api.GovernancePolicy {
	return governancePolicy
}

func GetCodeVersionStorage() *CodeVersionStorage {
	return codeVersionStorage
}

// -------------------------------------------------------------------------

func IsValidUpgradePath(initialVersion types.CodeVersion, targetVersion types.CodeVersion) bool {
	codeVersionStorage.Lock()
	defer codeVersionStorage.Unlock()

	if codeVersionStorage.SelfVersion != initialVersion {
		return false
	}

	return slices.Contains(codeVersionStorage.ValidUpdgradeVersions, targetVersion)
}

// -------------------------------------------------------------------------

func AppendUpgradePath(upgradePath types.UpgradePath) {
	codeVersionStorage.Lock()
	defer codeVersionStorage.Unlock()

	if !slices.Contains(upgradePath.InitialSet, codeVersionStorage.SelfVersion) {
		return
	}

	for _, version := range upgradePath.TargetSet {
		if !slices.Contains(codeVersionStorage.ValidUpdgradeVersions, version) {
			codeVersionStorage.ValidUpdgradeVersions = append(codeVersionStorage.ValidUpdgradeVersions, version)
		}
	}
}

func AddBannedVersion(codeVersion types.CodeVersion) {
	codeVersionStorage.Lock()
	defer codeVersionStorage.Unlock()

	codeVersionStorage.BannedVersions[codeVersion.CodeHash] = true
}

func CheckGovernanceHash(_governanceHash common.Hash) (bool, error) {
	governanceHash, err := governancePolicy.Hash()
	if err != nil {
		return false, err
	}
	if governanceHash != _governanceHash {
		return false, errors.New("governance hash mismatch")
	}

	return true, nil
}

func GeneratePausingNonce() common.Hash {
	// Todo: I'm not sure about this, it's a fallback to prevent the error case, since time based pseudo-randomness should be fine as a fallback
	nonce, err := utils.GenerateRandomBytes(32)
	if err != nil {
		// Fallback: less secure, but always passes
		// Seed math/rand using time
		rand2 := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
		for i := range nonce {
			nonce[i] = byte(rand2.Intn(256))
		}
	}

	nonceHash := common.BytesToHash(nonce)
	return nonceHash
}

func DestroyState() {
	governancePolicy = InitGovernancePolicy()
	codeVersionStorage = InitCodeVersionStorage()

	PausingAddressesStorage = InitPausingAddressesStorage()
	PausingNoncesStorage = InitPausingNonceStorage()
}
