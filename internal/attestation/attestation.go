package attestation

import (
	"crypto/x509"
	"encoding/hex"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/attestation"
	"github.com/flare-foundation/tee-node/pkg/types"

	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/tee"

	"github.com/pkg/errors"
)

var GoogleCert *x509.Certificate

func SetGoogleCert() error {
	var err error
	GoogleCert, err = attestation.LoadRootCert(settings.GoogleCertLoc)
	if err != nil {
		return err
	}

	return nil
}

func SelfAttest() error {
	tokeBytes, err := GetGoogleAttestationToken([]string{}, "PKI")
	if err != nil {
		return err
	}

	token, err := attestation.ValidatePKIToken(GoogleCert, string(tokeBytes))
	if err != nil {
		return err
	}
	ok, err := attestation.ValidateClaims(token, []string{})
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("failed validating token")
	}

	return nil
}

// ConstructTeeInfoResponse creates a tee info attestation response for the given challenge
func ConstructTeeInfoResponse(challenge common.Hash, nodeInfo *node.NodeInfo, initialID uint32, initialHash common.Hash, activeID uint32, activeHash common.Hash) (*types.TeeInfoResponse, error) {
	stEnc, err := nodeInfo.State.Encode()
	if err != nil {
		return nil, err
	}
	stHash := crypto.Keccak256(stEnc)

	teeInfo := tee.TeeStructsAttestation{
		Challenge:                challenge,
		PublicKey:                nodeInfo.PublicKey,
		InitialSigningPolicyId:   initialID,
		InitialSigningPolicyHash: initialHash,
		LastSigningPolicyId:      activeID,
		LastSigningPolicyHash:    activeHash,
		StateHash:                common.Hash(stHash),
		TeeTimestamp:             uint64(time.Now().Unix()),
	}

	enc, err := structs.Encode(tee.StructArg[tee.Attestation], teeInfo)
	if err != nil {
		return nil, err
	}
	h := crypto.Keccak256(enc)

	attestationBytes, err := GetGoogleAttestationToken([]string{hex.EncodeToString(h[:])}, attestation.PKITokenType)
	if err != nil {
		return nil, err
	}

	teeInfoResponse := types.TeeInfoResponse{
		TeeInfo:     teeInfo,
		State:       stEnc,
		Attestation: attestationBytes,
		Version:     settings.EncodingVersion,
	}

	return &teeInfoResponse, nil
}
