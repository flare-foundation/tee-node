package node

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/machinepath"
)

type Signer interface {
	Sign([]byte) ([]byte, error)
}

type Decrypter interface {
	Decrypt([]byte) ([]byte, error)
}

type Identifier interface {
	TeeID() common.Address
	ChainID() (uint64, error)
}

type Informer interface {
	Info() Info
}

type Configurer interface {
	SetOwner(common.Address) error
	SetExtensionID(common.Hash) error
	SetChainID(uint64) error
	SetGovernance(signers []common.Address, threshold uint64) error
}

type IdentifierAndSigner interface {
	Identifier
	Signer
}

type IdentifierSignerAndDecrypter interface {
	Identifier
	Signer
	Decrypter
}

// MachinePathLister exposes the governance-approved machine paths used
// to authorize direct-backup operations, along with the nonce of the
// last update.
type MachinePathLister interface {
	MachinePaths() ([]machinepath.IMachinePathManagerMachinePath, uint64)
}

// WalletNode is the capability set required by the wallet instruction
// processor: TEE identity, signing, decryption, and the machine-path
// allowlist. The chain ID needed by signing-hash helpers is reached via
// the embedded Identifier.ChainID().
type WalletNode interface {
	IdentifierSignerAndDecrypter
	MachinePathLister
}

type InformerAndSigner interface {
	Informer
	Signer
}
