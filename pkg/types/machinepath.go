package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/contracts/tee/machinepathmanager"
	"github.com/flare-foundation/go-flare-common/pkg/safe"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/machinepath"
)

// SetMachinePathListRequest is the JSON payload of a SET_MACHINE_PATH_LIST
// direct instruction: the active list of authorized machine paths, its
// monotonic nonce, and the governance authorization for it. A path authorizes
// any (source, destination) pair where source is in SourceTeeIds and
// destination is in DestinationTeeIds.
//
// Two authorization forms exist and either satisfies the node:
//   - Signatures: direct governance-signer ECDSA signatures over
//     signing.Payload{signing.TEEMachinePathList, chainID, MachinePathListDataHash(...)}
//     (collected from signMachinePathList transactions);
//   - SafeApproval: for a single approveMachinePathList call by the governance
//     Safe (Safe-backed governance only), the execTransaction parameter set
//     (owners' signatures blob included) and the Safe nonce it executed at. The
//     node reconstructs the Safe transaction hash at that nonce and re-verifies
//     the owner signatures itself.
type SetMachinePathListRequest struct {
	Paths        []machinepath.IMachinePathManagerMachinePath
	Nonce        uint64
	Signatures   [][]byte
	SafeApproval *safe.Approval `json:",omitempty"`
}

// ApproveMachinePathListCalldata returns the calldata of
// MachinePathManagerFacet.approveMachinePathList(extensionId, nonce,
// messageHash) — the inner call a governance Safe makes to approve a
// finalized machine path list. Verifiers compare a Safe execTransaction's
// `data` against this expected value to bind the approval to the full list
// content (messageHash commits to the paths).
func ApproveMachinePathListCalldata(
	extensionID common.Hash,
	nonce uint64,
	messageHash common.Hash,
) ([]byte, error) {
	// Derive both the selector and the argument encoding from the generated
	// MachinePathManager ABI, so a change to the on-chain signature is picked
	// up by regenerating the binding rather than editing this by hand.
	parsed, err := machinepathmanager.MachinePathManagerMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return parsed.Pack("approveMachinePathList",
		new(big.Int).SetBytes(extensionID[:]),
		new(big.Int).SetUint64(nonce),
		[32]byte(messageHash),
	)
}

// MachinePathListDataHash returns keccak256(abi.encode(extensionId,
// nonce, paths)) — the inner dataHash MachinePathManagerFacet.finalize
// wraps with SignedPayload.messageHash(TEE_MACHINE_PATH_LIST, ...) to
// produce the on-chain pathList.messageHash. Callers wrap this value
// with signing.Payload{signing.TEEMachinePathList, chainID, dataHash} before
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
