package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/convert"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/machinepath"
)

type InitializePolicyRequest struct {
	InitialPolicyBytes []byte
	PublicKeys         []PublicKey
}

type UpdatePolicyRequest struct {
	NewPolicy  MultiSignedPolicy
	PublicKeys []PublicKey
}

type MultiSignedPolicy struct {
	PolicyBytes []byte
	Signatures  [][]byte
}

// SetMachinePathListRequest is the JSON payload of a SET_MACHINE_PATH_LIST
// direct instruction: the active list of authorized machine paths, its
// monotonic nonce, and the governance signatures over
// DomainHash(MachinePathListDomainTag, chainID, MachinePathListDataHash(...)).
// A path authorizes any (source, destination) pair where source is in
// SourceTeeIds and destination is in DestinationTeeIds.
type SetMachinePathListRequest struct {
	Paths      []machinepath.IMachinePathManagerMachinePath
	Nonce      uint64
	Signatures [][]byte
}

// MachinePathListDomainTag is the bytes32 domain-separation tag embedded
// in the canonical hash, equal to bytes32("TEE_MACHINE_PATH_LIST") in the
// on-chain MachinePathManagerFacet. The error is unreachable: the tag is a
// fixed 21-character string, well under the 32-byte limit.
var MachinePathListDomainTag, _ = convert.StringToCommonHash("TEE_MACHINE_PATH_LIST")

// MachinePathListDataHash returns keccak256(abi.encode(extensionId,
// nonce, paths)) — the inner dataHash MachinePathManagerFacet.finalize
// wraps with SignedPayload.messageHash(TEE_MACHINE_PATH_LIST, ...) to
// produce the on-chain pathList.messageHash. Callers wrap this value
// with DomainHash(MachinePathListDomainTag, chainID, dataHash) before
// signing or comparing against the on-chain messageHash. paths is
// encoded as tuple(address[] sourceTeeIds, address[] destinationTeeIds)[].
func MachinePathListDataHash(
	extensionID common.Hash,
	nonce uint64,
	paths []machinepath.IMachinePathManagerMachinePath,
) (common.Hash, error) {
	uint256Ty, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return common.Hash{}, err
	}
	pathArrayTy, err := abi.NewType("tuple[]", "", []abi.ArgumentMarshaling{
		{Name: "sourceTeeIds", Type: "address[]"},
		{Name: "destinationTeeIds", Type: "address[]"},
	})
	if err != nil {
		return common.Hash{}, err
	}
	innerArgs := abi.Arguments{
		{Type: uint256Ty},
		{Type: uint256Ty},
		{Type: pathArrayTy},
	}
	innerEnc, err := innerArgs.Pack(
		new(big.Int).SetBytes(extensionID[:]),
		new(big.Int).SetUint64(nonce),
		paths,
	)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(innerEnc), nil
}
