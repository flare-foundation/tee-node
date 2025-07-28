package utils

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// Returns DER encoded signature from input hash
func SignECDSA(privKey, hash []byte) ([]byte, error) {
	// privateKey, err := crypto.ToECDSA(privKey)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// sig1, _ := crypto.Sign(hash, privateKey)

	priv, _ := btcec.PrivKeyFromBytes(privKey)
	sig2 := ecdsa.Sign(priv, hash)

	// fmt.Printf("Sig1: %X\n", sig1)
	// fmt.Printf("Sig2: %X\n", sig2.Serialize())

	return sig2.Serialize(), nil
}

// Verifies a hash using DER encoded signature
func VerifyECDSA(pubKey, signature, hash []byte) (bool, error) {
	sig, err := ecdsa.ParseDERSignature(signature)
	if err != nil {
		return false, err
	}
	pk, err := btcec.ParsePubKey(pubKey)
	if err != nil {
		return false, nil
	}
	return sig.Verify(hash, pk), nil

	// success := crypto.VerifySignature(pubKey, hash, signature)
	// return success, nil
}

func GetKeyPair(pkBytes []byte) (*btcec.PrivateKey, *btcec.PublicKey) {
	// fmt.Printf("PrivKey: %X\n", privKey.Serialize())
	// fmt.Printf("PubKey: %X\n", pubKey.SerializeCompressed())

	return btcec.PrivKeyFromBytes(pkBytes)
}
