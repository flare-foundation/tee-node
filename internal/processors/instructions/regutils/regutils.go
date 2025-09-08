package regutils

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/verification"
	"github.com/flare-foundation/tee-node/pkg/types"
)

func ValidateTeeAttestationRequest(attReq []byte, expectedTeeID common.Address) ([32]byte, error) {
	teeAttestationRequest, err := types.DecodeTeeAttestationRequest(attReq)
	if err != nil {
		return [32]byte{}, err
	}

	challenge, err := checkTeeAttestation(teeAttestationRequest, expectedTeeID)
	if err != nil {
		return [32]byte{}, err
	}

	return challenge, nil
}

func checkTeeAttestation(request verification.ITeeVerificationTeeAttestation, teeID common.Address) ([32]byte, error) {
	if request.TeeMachine.TeeId != teeID {
		return [32]byte{}, errors.New("TeeIds do not match")
	}
	if request.Challenge == [32]byte{} {
		return [32]byte{}, errors.New("challenge not given")
	}
	return request.Challenge, nil
}
