package types

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/tee/constants"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/tee"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/verification"
)

type TeeInfoRequest struct {
	Challenge common.Hash
}

type TeeInfoResponse struct {
	TeeInfo     tee.TeeStructsAttestation
	Attestation hexutil.Bytes
}

func EncodeTeeAttestationRequest(req *verification.ITeeVerificationTeeAttestation) (hexutil.Bytes, error) {
	arg := verification.MessageArguments[constants.TEEAttestation]
	return structs.Encode(arg, &req)
}

func DecodeTeeAttestationRequest(attReq []byte) (verification.ITeeVerificationTeeAttestation, error) {
	arg := verification.MessageArguments[constants.TEEAttestation]

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
