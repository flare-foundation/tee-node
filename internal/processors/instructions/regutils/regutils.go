package regutils

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/verification"
	"github.com/flare-foundation/tee-node/pkg/types"
)

// ValidateTeeAttestationRequest decodes the attestation payload and verifies it
// matches the expected TEE identity, returning the embedded challenge when
// successful.
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

// checkTeeAttestation ensures the decoded attestation request belongs to the
// expected TEE and that it carries a non-empty challenge.
func checkTeeAttestation(request verification.IVerificationTeeAttestation, teeID common.Address) ([32]byte, error) {
	if request.TeeMachine.TeeId != teeID {
		return [32]byte{}, errors.New("TeeIds do not match")
	}
	if request.Challenge == [32]byte{} {
		return [32]byte{}, errors.New("challenge not given")
	}
	return request.Challenge, nil
}
