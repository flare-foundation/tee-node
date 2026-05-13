package vrf_test

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
	"github.com/flare-foundation/go-flare-common/pkg/contracts/tee/vrfverifier"
	"github.com/flare-foundation/tee-node/pkg/wallets/vrf"
	"github.com/stretchr/testify/require"
)

// TestContractVerifyRandomness tests that the on-chain VRF verification logic matches the Go implementation
// and correctly rejects invalid proofs.
func TestContractVerifyRandomness(t *testing.T) {
	ctx := context.Background()

	privKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	deployerAddr := crypto.PubkeyToAddress(privKey.PublicKey)

	backend := simulated.NewBackend(types.GenesisAlloc{
		deployerAddr: {Balance: new(big.Int).Mul(big.NewInt(1e18), big.NewInt(10))},
	})
	defer backend.Close() //nolint:errcheck

	client := backend.Client()

	chainID, err := client.ChainID(ctx)
	require.NoError(t, err)

	auth, err := bind.NewKeyedTransactorWithChainID(privKey, chainID)
	require.NoError(t, err)
	auth.GasLimit = 3_000_000

	_, _, verifier, err := vrfverifier.DeployVRFVerifier(auth, client)
	require.NoError(t, err)
	backend.Commit() // mine the deployment transaction

	// ── Generate a VRF key used across subtests ───────────────────────────────
	key, err := crypto.GenerateKey()
	require.NoError(t, err)

	t.Run("valid proof", func(t *testing.T) {
		for range 5 {
			nonce := randomNonce(t)

			proof, err := vrf.VerifiableRandomness(key, nonce)
			require.NoError(t, err)

			valid, err := verifier.VerifyRandomness(
				&bind.CallOpts{Context: ctx},
				toContractProof(proof),
				key.X, key.Y,
				nonce,
			)
			require.NoError(t, err)
			require.True(t, valid, "verifyRandomness returned false for a valid proof")
		}
	})

	t.Run("randomness from proof matches contract", func(t *testing.T) {
		for range 5 {
			nonce := randomNonce(t)

			proof, err := vrf.VerifiableRandomness(key, nonce)
			require.NoError(t, err)

			contractRandom, err := verifier.RandomnessFromProof(
				&bind.CallOpts{Context: ctx},
				proof.Gamma.X, proof.Gamma.Y,
			)
			require.NoError(t, err)

			goRandom, err := proof.RandomnessFromProof()
			require.NoError(t, err)

			require.Equal(t, goRandom[:], contractRandom[:], "randomness output mismatch")
		}
	})

	t.Run("tampered challenge reverts", func(t *testing.T) {
		nonce := randomNonce(t)
		proof, err := vrf.VerifiableRandomness(key, nonce)
		require.NoError(t, err)

		badProof := toContractProof(proof)
		badProof.C = new(big.Int).Add(proof.C, big.NewInt(1)) // tamper

		_, err = verifier.VerifyRandomness(
			&bind.CallOpts{Context: ctx},
			badProof,
			key.X, key.Y,
			nonce,
		)
		require.Error(t, err, "tampered proof should cause the contract to revert")
	})

	t.Run("wrong nonce reverts", func(t *testing.T) {
		nonce := randomNonce(t)
		proof, err := vrf.VerifiableRandomness(key, nonce)
		require.NoError(t, err)

		_, err = verifier.VerifyRandomness(
			&bind.CallOpts{Context: ctx},
			toContractProof(proof),
			key.X, key.Y,
			randomNonce(t), // different nonce
		)
		require.Error(t, err, "wrong nonce should cause the contract to revert")
	})

	t.Run("wrong public key reverts", func(t *testing.T) {
		nonce := randomNonce(t)
		proof, err := vrf.VerifiableRandomness(key, nonce)
		require.NoError(t, err)

		otherKey, err := crypto.GenerateKey()
		require.NoError(t, err)

		_, err = verifier.VerifyRandomness(
			&bind.CallOpts{Context: ctx},
			toContractProof(proof),
			otherKey.X, otherKey.Y, // different key
			nonce,
		)
		require.Error(t, err, "wrong public key should cause the contract to revert")
	})
}

// toContractProof converts a Go VRF proof into the struct expected by the
// VRFVerifier Solidity contract. Witness points are read directly from the
// proof since VerifiableRandomness now populates them.
func toContractProof(proof *vrf.Proof) vrfverifier.IVrfVerifierProof {
	return vrfverifier.IVrfVerifierProof{
		Gamma:  vrfverifier.IVrfVerifierPoint{X: proof.Gamma.X, Y: proof.Gamma.Y},
		C:      proof.C,
		S:      proof.S,
		U:      vrfverifier.IVrfVerifierPoint{X: proof.U.X, Y: proof.U.Y},
		CGamma: vrfverifier.IVrfVerifierPoint{X: proof.CGamma.X, Y: proof.CGamma.Y},
		V:      vrfverifier.IVrfVerifierPoint{X: proof.V.X, Y: proof.V.Y},
		ZInv:   proof.ZInv,
	}
}
