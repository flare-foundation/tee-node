package types

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/tee"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/verification"
)

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
	State                    TeeState    `json:"state"`
	TeeTimestamp             uint64      `json:"teeTimestamp"`
}

func (ti *TeeInfo) Hash() ([]byte, error) {
	enc, err := structs.Encode(tee.StructArg[tee.Attestation], ti.prepareForEncoding())
	if err != nil {
		return nil, err
	}

	return crypto.Keccak256(enc), nil
}

func (ti *TeeInfo) prepareForEncoding() tee.TeeStructsAttestation {
	return tee.TeeStructsAttestation{
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
		TeeTimestamp: ti.TeeTimestamp,
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
	TeeInfo     TeeInfo       `json:"teeInfo"`
	Attestation hexutil.Bytes `json:"attestation"`
}

type SignedTeeInfoResponse struct {
	TeeInfoResponse
	ProxySignature hexutil.Bytes `json:"proxySignature"`
}

func EncodeTeeAttestationRequest(req *verification.ITeeVerificationTeeAttestation) (hexutil.Bytes, error) {
	arg := verification.MessageArguments[op.TEEAttestation]
	return structs.Encode(arg, &req)
}

func DecodeTeeAttestationRequest(attReq []byte) (verification.ITeeVerificationTeeAttestation, error) {
	arg := verification.MessageArguments[op.TEEAttestation]

	var unpacked verification.ITeeVerificationTeeAttestation
	err := structs.DecodeTo(arg, attReq, &unpacked)
	if err != nil {
		return verification.ITeeVerificationTeeAttestation{}, err
	}

	return unpacked, nil
}

type ConfigureProxyUrlRequest struct {
	Url string
}
