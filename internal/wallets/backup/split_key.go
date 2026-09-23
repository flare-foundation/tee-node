package backup

import (
	"errors"
	"fmt"

	"filippo.io/bigmod"

	"github.com/flare-foundation/tee-node/pkg/wallets/backup"
)

// SplitSecret splits a secret into n additive parts over the field, such that
// the parts sum to the secret. Each part is returned in the field's fixed-width
// encoding. The secret must be exactly the field's secret width and smaller
// than its modulus.
//
// Every part is uniformly distributed, so any proper subset reveals nothing
// about the secret.
func SplitSecret(field *backup.Field, secret []byte, n int) ([][]byte, error) {
	if n < 2 {
		return nil, errors.New("number of splits too low")
	}
	// Exactly the field's width, so the secret comes back byte for byte: a
	// shorter one would be recovered with leading zeros it never had.
	if len(secret) != field.SecretSize {
		return nil, fmt.Errorf("secret is %d bytes, but the field shares %d-byte secrets", len(secret), field.SecretSize)
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
// returned at the field's secret width.
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

	return field.SecretBytes(sum)
}
