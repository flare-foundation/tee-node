package types

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/machine"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/tee"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/verification"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
)

// KeyExistenceDataHash returns keccak256(abi.encode(proof)), the inner
// dataHash WalletKeyManagerFacet.confirmKey wraps with
// SignedPayload.messageHash(TEE_KEY_EXISTENCE, ...). Callers wrap this
// value with signing.Payload{csigning.TEEKeyExistence, chainID, dataHash}.Hash()
// before signing or comparing.
func KeyExistenceDataHash(proof *wallet.IWalletKeyManagerKeyExistence) (common.Hash, error) {
	if proof == nil {
		return common.Hash{}, errors.New("key existence data hash requires a non-nil proof")
	}

	innerEnc, err := abi.Arguments{wallet.KeyExistenceStructArg}.Pack(*proof)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(innerEnc), nil
}

type TeeInfoRequest struct {
	Challenge common.Hash
}

type TeeInfo struct {
	Challenge                common.Hash `json:"challenge"`
	PublicKey                PublicKey   `json:"publicKey"`
	InitialSigningPolicyID   uint32      `json:"initialSigningPolicyId"`
	InitialSigningPolicyHash common.Hash `json:"initialSigningPolicyHash"`
	LastSigningPolicyID      uint32      `json:"lastSigningPolicyId"`
	LastSigningPolicyHash    common.Hash `json:"lastSigningPolicyHash"`
	ChainID                  uint64      `json:"chainId"`
	State                    TeeState    `json:"state"`
	TeeTimestamp             uint64      `json:"teeTimestamp"`
	MachinePathListNonce     uint64      `json:"machinePathListNonce"`
	MachinePathListHash      common.Hash `json:"machinePathListHash"`
}

// Hash encodes and hashes the TEE attestation payload.
func (ti *TeeInfo) Hash() ([]byte, error) {
	enc, err := structs.Encode(tee.StructArg[tee.Attestation], ti.prepareForEncoding())
	if err != nil {
		return nil, err
	}

	return crypto.Keccak256(enc), nil
}

func (ti *TeeInfo) prepareForEncoding() tee.TeeStructsAttestation {
	return tee.TeeStructsAttestation{
		ChainId:   new(big.Int).SetUint64(ti.ChainID),
		Challenge: ti.Challenge,
		PublicKey: tee.PublicKey{
			X: ti.PublicKey.X,
			Y: ti.PublicKey.Y,
		},
		InitialSigningPolicyId:   ti.InitialSigningPolicyID,
		InitialSigningPolicyHash: ti.InitialSigningPolicyHash,
		LastSigningPolicyId:      ti.LastSigningPolicyID,
		LastSigningPolicyHash:    ti.LastSigningPolicyHash,
		State: tee.ITeeAvailabilityCheckTeeState{
			SystemState:        ti.State.SystemState,
			SystemStateVersion: ti.State.SystemStateVersion,
			State:              ti.State.State,
			StateVersion:       ti.State.StateVersion,
		},
		TeeTimestamp:         ti.TeeTimestamp,
		MachinePathListNonce: new(big.Int).SetUint64(ti.MachinePathListNonce),
		MachinePathListHash:  ti.MachinePathListHash,
	}
}

type PublicKey struct {
	X common.Hash `json:"x"`
	Y common.Hash `json:"y"`
}

type TeeState struct {
	SystemState        hexutil.Bytes `json:"systemState"`
	SystemStateVersion common.Hash   `json:"systemStateVersion"`
	State              hexutil.Bytes `json:"state"`
	StateVersion       common.Hash   `json:"stateVersion"`
}

type TeeInfoResponse struct {
	TeeInfo       TeeInfo       `json:"teeInfo"`
	MachineData   MachineData   `json:"machineData"`
	DataSignature hexutil.Bytes `json:"dataSignature"`
	Attestation   string        `json:"attestation"`
}

type MachineData struct {
	ExtensionID    common.Hash    `json:"extensionId"`
	InitialOwner   common.Address `json:"initialOwner"`
	CodeHash       common.Hash    `json:"codeHash"`
	Platform       common.Hash    `json:"platform"`
	PublicKey      PublicKey      `json:"publicKey"`
	GovernanceHash common.Hash    `json:"governanceHash"`
}

// DataHash returns keccak256(abi.encode(teeMachineData)) — the inner
// dataHash MachineManagerFacet.register wraps with
// SignedPayload.messageHash(TEE_MACHINE_REGISTER, ...). Callers wrap
// this value with signing.Payload{TeeMachineRegisterTag, chainID,
// dataHash}.Hash() before signing or comparing.
func (md *MachineData) DataHash() (common.Hash, error) {
	innerEnc, err := abi.Arguments{machine.TeeMachineDataStructArg}.Pack(md.prepareForEncoding())
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(innerEnc), nil
}

func (md *MachineData) prepareForEncoding() machine.IMachineManagerTeeMachineData {
	return machine.IMachineManagerTeeMachineData{
		ExtensionId:  md.ExtensionID.Big(),
		InitialOwner: md.InitialOwner,
		CodeHash:     md.CodeHash,
		Platform:     md.Platform,
		PublicKey: machine.PublicKey{
			X: md.PublicKey.X,
			Y: md.PublicKey.Y,
		},
		GovernanceHash: md.GovernanceHash,
	}
}

type SignedTeeInfoResponse struct {
	TeeInfoResponse
	ProxySignature hexutil.Bytes `json:"proxySignature"`
}

// EncodeTeeAttestationRequest serializes the attestation request using the
// generated struct ABI.
func EncodeTeeAttestationRequest(req *verification.IVerificationTeeAttestation) (hexutil.Bytes, error) {
	arg := verification.MessageArguments[op.TEEAttestation]
	return structs.Encode(arg, &req)
}

// DecodeTeeAttestationRequest decodes the attestation request bytes into the
// strongly typed struct.
func DecodeTeeAttestationRequest(attReq []byte) (verification.IVerificationTeeAttestation, error) {
	arg := verification.MessageArguments[op.TEEAttestation]

	var unpacked verification.IVerificationTeeAttestation
	err := structs.DecodeTo(arg, attReq, &unpacked)
	if err != nil {
		return verification.IVerificationTeeAttestation{}, err
	}

	return unpacked, nil
}

type ConfigureProxyURLRequest struct {
	URL *string `json:"url"` // The pointer ensures {} and {"url": ""} unmarshal distinctly.

}

type ConfigureInitialOwnerRequest struct {
	Owner *common.Address `json:"owner"`
}

type ConfigureExtensionIDRequest struct {
	ExtensionID *common.Hash `json:"extensionId"`
}

type ConfigureChainIDRequest struct {
	ChainID *uint64 `json:"chainId"`
}

// Governance is the governance signer-set known to the node. Hash is
// keccak256(abi.encode(Signers, Threshold)), the same value stored
// on-chain as governanceHash.
type Governance struct {
	Signers   []common.Address `json:"signers"`
	Threshold uint64           `json:"threshold"`
	Hash      common.Hash      `json:"hash"`
}

type ConfigureGovernanceRequest struct {
	Signers   *[]common.Address `json:"signers"`
	Threshold *uint64           `json:"threshold"`
}

// GovernanceHash returns keccak256(abi.encode(address[], uint256)) for the
// given (signers, threshold) tuple — the same value the on-chain contract
// stores as `bytes32 governanceHash`.
func GovernanceHash(signers []common.Address, threshold uint64) (common.Hash, error) {
	addressArrayTy, err := abi.NewType("address[]", "", nil)
	if err != nil {
		return common.Hash{}, err
	}
	uint256Ty, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return common.Hash{}, err
	}
	args := abi.Arguments{{Type: addressArrayTy}, {Type: uint256Ty}}
	enc, err := args.Pack(signers, new(big.Int).SetUint64(threshold))
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(enc), nil
}
