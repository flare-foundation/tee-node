package main

import (
	"crypto/ecdsa"
	"fmt"
	"tee-node/pkg/utils"
	"tee-node/tests/client/xrpl"

	xrputils "tee-node/tests/client/xrpl/utils"

	"github.com/ethereum/go-ethereum/crypto"
)

func SignMultisigTransactionExample() {

	amount := uint64(9950000)
	fee := uint64(990)
	spenderAccount := "rPp11a5qy4wJRj4di4buquo1Ftao4GLKe8" // Address of the Multisig account
	destinationAccount := "rN5N6fJbc8xyViPDeQFMQMpYfVHuxSGV2G"
	sequence := uint32(4245345)
	lastLedgerSeq := uint32(5050107)

	// Construct the payment transaction
	payment, _ := xrpl.ConstructPaymentTransaction(amount, fee, spenderAccount, destinationAccount, sequence, lastLedgerSeq)

	// Generate 3 private keys and derive the corresponding addresses
	// nKeys := 3
	// privKeys := generateMockPrivKeys(nKeys)
	pks := []string{"089287075791EC70BE4A61B8768825148FF38660C00EEFDE029C0AD173610B16", "F35F6F5ECF80BBC31AD8A04218CE4001FB85E0BAA846550B2FEC60885C5BF41B", "68930A6C60B6E5943C2297947A03FBA5CA63379B4CEFCFF897A9D79BEEA29C90"}
	privKeys := make([]*ecdsa.PrivateKey, len(pks))
	for i, pk := range pks {
		rivKey, _ := crypto.HexToECDSA(pk)
		privKeys[i] = rivKey
	}

	addresses := deriveMockAddresses(privKeys)

	signers := make([]xrputils.Signer, len(privKeys))
	for i := 0; i < len(privKeys); i++ {

		// Encode the transaction to a byte[] required for signing
		// Note: The address is required for encoding the transaction (meaning each signer will sign a different txHash)
		encodedTx, _ := xrpl.EncodeTransaction(payment, addresses[i])

		// compute the hash of the payment transaction
		txHash := xrpl.HashXRPMessage(encodedTx)

		// Sign the transaction
		txnSignature := utils.XrpSign(txHash, privKeys[i])

		pubKeyBytes := utils.SerializeCompressed(&privKeys[i].PublicKey) // The compressed format required by ripple

		// Construct the SignerItem (The format expected by the xrp client)
		signer, _ := xrpl.ConstructSignerItem(addresses[i], txnSignature, pubKeyBytes)

		// Append the SignerItem to the list of signers
		signers[i] = *signer

		// Check that the signature is valid
		valid, _ := utils.XrpVerifySig(txHash, txnSignature, &privKeys[i].PublicKey)
		if !valid {
			panic("Signature is invalid")
		}
	}

	// Append the signers to the payment transaction
	payment.Signers = append(payment.Signers, signers...)

	for _, signer := range payment.Signers {
		fmt.Printf("Signer: %s\n", signer.Signer.String())
	}

	// fmt.Printf("Payment transaction signed successfully: %v\n", payment.Signers)
}

// ----- Helper functions ----- //
// func generateMockPrivKeys(n int) []*ecdsa.PrivateKey {
// 	privKeys := make([]*ecdsa.PrivateKey, n)
// 	for i := 0; i < n; i++ {
// 		privKey, _ := crypto.GenerateKey()
// 		privKeys[i] = privKey
// 	}
// 	return privKeys
// }

func deriveMockAddresses(privKeys []*ecdsa.PrivateKey) []string {
	addresses := make([]string, len(privKeys))
	for i, privKey := range privKeys {
		pkBytes := utils.SerializeCompressed(&privKey.PublicKey) // The compressed format required by ripple
		pubKey := xrputils.PublicKey(pkBytes)
		addresses[i] = pubKey.Address()
	}
	return addresses
}

func Main() {
	SignMultisigTransactionExample()
}
