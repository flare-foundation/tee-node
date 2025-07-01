package types

import (
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/constants"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/verification"
)

type TeeInfo struct {
	Challenge                common.Hash
	PublicKey                ECDSAPublicKey
	Status                   string
	InitialSigningPolicyId   uint32
	InitialSigningPolicyHash common.Hash
	LastSigningPolicyId      uint32
	LastSigningPolicyHash    common.Hash
	Nonce                    uint64
	PauseNonce               uint64
	TeeTimestamp             int64
}

func (teeInfo TeeInfo) Hash() (common.Hash, error) {
	encoded, err := json.Marshal(teeInfo)
	if err != nil {
		return common.Hash{}, err
	}
	hash := crypto.Keccak256(encoded)
	var res common.Hash
	copy(res[:], hash)

	return res, nil
}

type TeeInfoRequest struct {
	Challenge common.Hash
}

type TeeInfoResponse struct {
	TeeInfo
	Attestation hexutil.Bytes
}

func ParseTeeAttestationRequest(instructionData *instruction.DataFixed) (verification.ITeeVerificationTeeAttestation, error) {
	arg := verification.MessageArguments[constants.TEEAttestation]

	var unpacked verification.ITeeVerificationTeeAttestation
	err := structs.DecodeTo(arg, instructionData.OriginalMessage, &unpacked)
	if err != nil {
		return verification.ITeeVerificationTeeAttestation{}, err
	}

	return unpacked, nil
}
