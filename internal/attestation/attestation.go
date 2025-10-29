package attestation

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"

	"github.com/ethereum/go-ethereum/common"
	googlecloud "github.com/flare-foundation/go-flare-common/pkg/tee/attestation/google_cloud"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/attestation"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/types"
)

var GoogleCert *x509.Certificate

// SetGoogleCert loads the Google root certificate into memory for attestation
// validation.
func SetGoogleCert() error {
	var err error
	GoogleCert, err = attestation.LoadRootCert(settings.GoogleCertLoc)
	if err != nil {
		return err
	}

	return nil
}

// SelfAttest performs a local attestation cycle, falling back to MagicPass in
// non-production modes.
func SelfAttest() error {
	tokeBytes, err := GetGoogleAttestationToken([]string{}, "PKI")
	if err != nil {
		return err
	}
	if string(tokeBytes) == attestation.MagicPass {
		return nil
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

// ConstructTEEInfoResponse creates a tee info attestation response for the given challenge
func ConstructTEEInfoResponse(challenge common.Hash, nodeInfo *node.Info, initialID uint32, initialHash common.Hash, activeID uint32, activeHash common.Hash) (*types.TeeInfoResponse, error) {
	state, err := nodeInfo.State.State()
	if err != nil {
		return nil, err
	}

	teeInfo := types.TeeInfo{
		Challenge:                challenge,
		PublicKey:                nodeInfo.PublicKey,
		InitialSigningPolicyID:   initialID,
		InitialSigningPolicyHash: initialHash,
		LastSigningPolicyID:      activeID,
		LastSigningPolicyHash:    activeHash,
		State:                    state,
		TeeTimestamp:             uint64(time.Now().Unix()),
	}

	h, err := teeInfo.Hash()
	if err != nil {
		return nil, err
	}

	attestationBytes, err := GetGoogleAttestationToken([]string{hex.EncodeToString(h)}, attestation.PKITokenType)
	if err != nil {
		return nil, err
	}

	var cHash common.Hash
	var platform common.Hash

	if settings.Mode == 0 {
		_, claims, err := googlecloud.ParsePKITokenUnverified(string(attestationBytes))
		if err != nil {
			return nil, err
		}

		cHash, err = claims.CodeHash()
		if err != nil {
			return nil, err
		}

		platform, err = claims.Platform()
		if err != nil {
			return nil, err
		}
	}

	mData := types.MachineData{
		ExtensionID:  nodeInfo.ExtensionID,
		InitialOwner: nodeInfo.InitialOwner,
		CodeHash:     cHash,
		Platform:     platform,
		PublicKey:    nodeInfo.PublicKey,
	}

	teeInfoResponse := types.TeeInfoResponse{
		TeeInfo:     teeInfo,
		MachineData: mData,
		Attestation: attestationBytes,
	}

	return &teeInfoResponse, nil
}
