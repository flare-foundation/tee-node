package wallets

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/hash"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/wallets/vrf"
)

type Signer interface {
	Sign([]byte) ([]byte, error)
}

// signSHA512HalfSecp256k1ECDSA hashes the message using (XRPL's) SHA512Half and returns the recoverable ECDSA signature of the digest.
// It uses the curve Secp256k1.
// The signature has format [R || S || V] where V is 0 or 1, and R and S have 32 bytes each.
func signSHA512HalfSecp256k1ECDSA(privateKey *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	hash := hash.Sha512Half(msg)
	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// signKeccak256Secp256k1ECDSA hashes the message using Keccak256 and returns the recoverable ECDSA signature of the digest.
// It uses the curve Secp256k1.
// The signature has format [R || S || V] where V is 0 or 1, and R and S have 32 bytes each.
func signKeccak256Secp256k1ECDSA(privateKey *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	hash := crypto.Keccak256(msg)
	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func signVRF(privateKey *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	signature, err := vrf.VerifiableRandomness(privateKey, msg)
	if err != nil {
		return nil, err
	}

	return json.Marshal(signature)
}

func verifySHA512HalfSecp256k1ECDSA(msg, signature, publicKey []byte) error {
	pk, err := types.ParsePubKeyBytes(publicKey)
	if err != nil {
		return err
	}
	msgHash := hash.Sha512Half(msg)
	recovered, err := crypto.SigToPub(msgHash, signature)
	if err != nil {
		return err
	}
	if crypto.PubkeyToAddress(*recovered) != crypto.PubkeyToAddress(*pk) {
		return errors.New("signature verification failed: signer mismatch")
	}
	return nil
}

func verifyKeccak256Secp256k1ECDSA(msg, signature, publicKey []byte) error {
	pk, err := types.ParsePubKeyBytes(publicKey)
	if err != nil {
		return err
	}
	msgHash := crypto.Keccak256(msg)
	recovered, err := crypto.SigToPub(msgHash, signature)
	if err != nil {
		return err
	}
	if crypto.PubkeyToAddress(*recovered) != crypto.PubkeyToAddress(*pk) {
		return errors.New("signature verification failed: signer mismatch")
	}
	return nil
}

func verifyVRF(msg, signature, publicKey []byte) error {
	pk, err := types.ParsePubKeyBytes(publicKey)
	if err != nil {
		return err
	}
	var proof vrf.Proof
	if err := json.Unmarshal(signature, &proof); err != nil {
		return err
	}
	return vrf.VerifyRandomness(&proof, pk, msg)
}
