package backup

import (
	"errors"
	"fmt"

	"filippo.io/bigmod"

	"github.com/flare-foundation/tee-node/pkg/wallets/backup"
)

// SplitSecret splits a secret into n additive parts over the field, such that
// the parts sum to the secret. Each part is returned in the field's fixed-width
// encoding. The secret must be smaller than the field modulus.
//
// Every part is uniformly distributed, so any proper subset reveals nothing
// about the secret.
func SplitSecret(field *backup.Field, secret []byte, n int) ([][]byte, error) {
	if n < 2 {
		return nil, errors.New("number of splits too low")
	}

	secretElem, err := field.Element(secret)
	if err != nil {
		return nil, fmt.Errorf("secret does not fit the sharing field: %w", err)
	}

	parts := make([][]byte, n)
	sum := bigmod.NewNat().ExpandFor(field.Modulus)

	for i := range n - 1 {
		part, err := field.Random()
		if err != nil {
			return nil, err
		}

		parts[i] = field.Bytes(part)
		sum.Add(part, field.Modulus)
	}

	// The final part absorbs the difference so the parts sum to the secret.
	last := bigmod.NewNat().ExpandFor(field.Modulus)
	last.Add(secretElem, field.Modulus)
	last.Sub(sum, field.Modulus)
	parts[n-1] = field.Bytes(last)

	return parts, nil
}

// JoinSecret recombines additive parts into the secret they were split from,
// returned in the field's fixed-width encoding.
func JoinSecret(field *backup.Field, parts ...[]byte) ([]byte, error) {
	if len(parts) == 0 {
		return nil, errors.New("no parts")
	}

	sum := bigmod.NewNat().ExpandFor(field.Modulus)
	for i, part := range parts {
		elem, err := field.Element(part)
		if err != nil {
			return nil, fmt.Errorf("part %d: %w", i, err)
		}
		sum.Add(elem, field.Modulus)
	}

	return field.Bytes(sum), nil
}
