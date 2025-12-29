package attestation

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/convert"
	"github.com/flare-foundation/go-flare-common/pkg/tee/attestation/googlecloud"
	"github.com/golang-jwt/jwt/v5"
)

type TokenType string

const PKITokenType = TokenType("PKI")
const OIDCTokenType = TokenType("OIDC") // currently not used
const MagicPass = "magic_pass"          // only for testing outside of the google cloud

// GoogleTeeClaims represents the claims present in a Google Cloud TEE attestation JWT.
//
// Based on https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims.
type NeededClaims struct {
	HWModel string  `json:"hwmodel"`
	SubMods SubMods `json:"submods"`
	jwt.RegisteredClaims
}

func (c *NeededClaims) Platform() (common.Hash, error) {
	p, err := convert.StringToCommonHash(c.HWModel)
	if err != nil {
		return common.Hash{}, fmt.Errorf("unparsable HWModel: %w", err)
	}

	return p, nil
}

func (c *NeededClaims) CodeHash() (common.Hash, error) {
	ch, err := convert.Hex32StringToCommonHash(strings.TrimPrefix(c.SubMods.Container.ImageDigest, "sha256:"))
	if err != nil {
		return common.Hash{}, fmt.Errorf("unparsable ImageDigest: %w", err)
	}

	return ch, nil
}

type SubMods struct {
	Container Container `json:"container"`
}

type Container struct {
	ImageDigest string `json:"image_digest"`
}

// LoadRootCert reads and parses the PEM-encoded root certificate.
func LoadRootCert(fileName string) (*x509.Certificate, error) {
	rootCertBytes, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read root certificate: %w", err)
	}

	cert, err := googlecloud.ParsePEMCertificate(string(rootCertBytes))

	return cert, err
}
