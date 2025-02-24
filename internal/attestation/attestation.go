package attestation

import (
	"crypto/x509"
	"fmt"
	"tee-node/config"

	"github.com/pkg/errors"
)

var GoogleCert *x509.Certificate

func SetGoogleCert() error {
	var err error
	GoogleCert, err = LoadRootCert("google_confidential_space_root.crt") // todo
	if err != nil {
		return err
	}

	return nil
}

func SelfAttest() error {
	if config.Mode != 0 {
		return nil
	}

	tokeBytes, err := GetGoogleAttestationToken([]string{}, "PKI")
	fmt.Println(tokeBytes, err)
	if err != nil {
		return err
	}

	token, err := ValidatePKIToken(*GoogleCert, string(tokeBytes))
	if err != nil {
		return err
	}
	ok, err := ValidateClaims(token, []string{})
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("failed validating token")
	}

	return nil
}
