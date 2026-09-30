package backup

import (
	"errors"
	"fmt"
	"slices"

	"filippo.io/bigmod"

	"github.com/flare-foundation/tee-node/pkg/wallets/backup"
)

// SplitToShamirShares generates Shamir secret shares for the provided value
// over the given field. The value must be smaller than the field modulus, which
// is what makes sharing injective; callers select the field from the key's
// metadata so this holds by construction.
//
// Polynomial evaluation uses constant-time modular arithmetic, so neither the
// secret nor the sampled coefficients influence execution time.
func SplitToShamirShares(field *backup.Field, val []byte, numShares uint64, threshold uint64) ([]backup.ShamirShare, error) {
	// Verify minimum isn't greater than shares; there is no way to recreate
	// the original polynomial in our current setup, therefore it doesn't make
	// sense to generate fewer shares than are needed to reconstruct the secret.
	if threshold > numShares {
		return nil, errors.New("num shares smaller than threshold")
	}
	if threshold == 0 {
		return nil, errors.New("threshold should be positive")
	}

	secret, err := field.Element(val)
	if err != nil {
		return nil, fmt.Errorf("secret does not fit the sharing field: %w", err)
	}

	polynomial := make([]*bigmod.Nat, threshold)
	polynomial[0] = secret
	for i := uint64(1); i < threshold; i++ {
		polynomial[i], err = field.Random()
		if err != nil {
			return nil, err
		}
	}

	shamirShares := make([]backup.ShamirShare, numShares)
	for i := range numShares {
		x := i + 1
		shamirShares[i] = backup.ShamirShare{
			X: x,
			Y: field.Bytes(evalPolynomial(field, polynomial, x)),
		}
	}

	return shamirShares, nil
}

// evalPolynomial evaluates the polynomial at x by Horner's method. The
// polynomial must have at least one coefficient.
func evalPolynomial(field *backup.Field, polynomial []*bigmod.Nat, x uint64) *bigmod.Nat {
	xElem := field.ElementFromUint64(x)

	// Starting from zero folds the leading coefficient in on the first
	// iteration, so no separate copy of it is needed.
	result := bigmod.NewNat().ExpandFor(field.Modulus)
	for _, coefficient := range slices.Backward(polynomial) {
		result.Mul(xElem, field.Modulus)
		result.Add(coefficient, field.Modulus)
	}

	return result
}

// CombineShamirShares joins shares assuming that the threshold is at
// exactly the length of the input. The share values are secret and are combined
// with constant-time arithmetic; the evaluation indices are public, so the
// Lagrange denominators are inverted in variable time.
func CombineShamirShares(field *backup.Field, shamirShares []backup.ShamirShare) ([]byte, error) {
	result := bigmod.NewNat().ExpandFor(field.Modulus)

	// The evaluation indices are reused across every basis polynomial, so they
	// are converted once rather than per inner iteration.
	xs := make([]*bigmod.Nat, len(shamirShares))
	for i, share := range shamirShares {
		xs[i] = field.ElementFromUint64(share.X)
	}

	// Lagrange interpolation. The numerator and denominator of each basis
	// polynomial are accumulated as products and divided once, so the number of
	// modular inversions is linear in the share count rather than quadratic.
	for i, share := range shamirShares {
		y, err := field.Element(share.Y)
		if err != nil {
			return nil, fmt.Errorf("share %d: %w", i, err)
		}

		numerator := bigmod.NewNat().SetUint(1).ExpandFor(field.Modulus)
		denominator := bigmod.NewNat().SetUint(1).ExpandFor(field.Modulus)

		for j, shareJ := range shamirShares {
			if i == j {
				continue
			}
			if shareJ.X == share.X {
				// Duplicate detection upstream should reject this first; a
				// repeated index makes the denominator zero and the
				// interpolation undefined.
				return nil, errors.New("double share error")
			}

			numerator.Mul(xs[j], field.Modulus)

			difference := field.ElementFromUint64(shareJ.X)
			difference.Sub(xs[i], field.Modulus)
			denominator.Mul(difference, field.Modulus)
		}

		// Inverting in variable time is safe here because the denominator is
		// derived only from the evaluation indices, which are public.
		inverse, ok := bigmod.NewNat().InverseVarTime(denominator, field.Modulus)
		if !ok {
			return nil, errors.New("double share error")
		}

		result.Add(y.Mul(numerator, field.Modulus).Mul(inverse, field.Modulus), field.Modulus)
	}

	return field.Bytes(result), nil
}
