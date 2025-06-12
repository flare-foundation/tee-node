package xrpl_test

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"tee-node/pkg/tee/utils"
	xrpl "tee-node/testutils/xrpl"
	xrputils "tee-node/testutils/xrpl/utils"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestSignAndVerifyTransaction(t *testing.T) {

	payment, err := getSampleTransaction()
	if err != nil {
		t.Fatalf("failed to get sample transaction: %v", err)
	}

	privKey1 := "089287075791EC70BE4A61B8768825148FF38660C00EEFDE029C0AD173610B16"
	privKey2 := "F35F6F5ECF80BBC31AD8A04218CE4001FB85E0BAA846550B2FEC60885C5BF41B"
	privKey3 := "68930A6C60B6E5943C2297947A03FBA5CA63379B4CEFCFF897A9D79BEEA29C90"

	// pubKey1 := "02707A7AE05A8DACDB89CC93429949CDA26F68200D9CE8753D4DCB04D6F80CFCB7"
	// pubKey2 := "035DB05B1CEA82785FB8B3F7E68E5C7429A1B00BE47CC6B1A651AA12C7B8D9592C"
	// pubKey3 := "030C141E3E131B1D25B7EA85B10283E315F77F27A2FA085A45D65D47393DB9219F"

	addr1 := "rN5N6fJbc8xyViPDeQFMQMpYfVHuxSGV2G"
	addr2 := "rJQesZZEQzW9J3Eb1X1Snc7E6YGk7kTMoK"
	addr3 := "r9cvJhquqeExszdWZSw2rrFP98fsVFLdPe"

	encodedTx1, err1 := xrpl.EncodeTransaction(payment, addr1)
	encodedTx2, err2 := xrpl.EncodeTransaction(payment, addr2)
	encodedTx3, err3 := xrpl.EncodeTransaction(payment, addr3)

	str1 := strings.ToLower(hex.EncodeToString(encodedTx1))
	str2 := strings.ToLower(hex.EncodeToString(encodedTx2))
	str3 := strings.ToLower(hex.EncodeToString(encodedTx3))

	reference1 := strings.ToLower("534D54001200002200000000240040C75B201B0048BB5361400000000097D3306840000000000003DE73008114F1ADA4636583E2DD405AF86AC98145D180B22F01831496661E656F4E0995FB56E0AF6A69846107E0C8CF96661E656F4E0995FB56E0AF6A69846107E0C8CF")
	if str1 != reference1 {
		t.Fatalf("encodedTx1: %v \nError:%e\n", str1, err1)
	}
	reference2 := strings.ToLower("534D54001200002200000000240040C75B201B0048BB5361400000000097D3306840000000000003DE73008114F1ADA4636583E2DD405AF86AC98145D180B22F01831496661E656F4E0995FB56E0AF6A69846107E0C8CFBEF2A0DBC34168D454B6C642957D9A65E637EDE9")
	if str2 != reference2 {
		t.Fatalf("encodedTx2: %v \nError:%e\n", str2, err2)
	}
	reference3 := strings.ToLower("534D54001200002200000000240040C75B201B0048BB5361400000000097D3306840000000000003DE73008114F1ADA4636583E2DD405AF86AC98145D180B22F01831496661E656F4E0995FB56E0AF6A69846107E0C8CF5E8C0D7FA50E2334C0D6C9C6767926E46C1E6AE7")
	if str3 != reference3 {
		t.Fatalf("encodedTx3: %v \nError:%e\n", str3, err3)
	}

	t.Logf("Transactions Encoded Successfully\n")

	txHash1 := xrpl.HashXRPMessage(encodedTx1)
	txHash2 := xrpl.HashXRPMessage(encodedTx2)
	txHash3 := xrpl.HashXRPMessage(encodedTx3)

	pk1, _ := crypto.HexToECDSA(privKey1)
	pk2, _ := crypto.HexToECDSA(privKey2)
	pk3, _ := crypto.HexToECDSA(privKey3)

	sig1 := utils.XrpSign(txHash1, pk1)
	sig2 := utils.XrpSign(txHash2, pk2)
	sig3 := utils.XrpSign(txHash3, pk3)

	valid1, err1 := xrpl.XrpVerifySig(txHash1, sig1, &pk1.PublicKey)
	if err1 != nil {
		t.Fatalf("error verifying signature 1: %v", err1)
	}

	valid2, err2 := xrpl.XrpVerifySig(txHash2, sig2, &pk2.PublicKey)
	if err2 != nil {
		t.Fatalf("error verifying signature 2: %v", err2)
	}

	valid3, err3 := xrpl.XrpVerifySig(txHash3, sig3, &pk3.PublicKey)
	if err3 != nil {
		t.Fatalf("error verifying signature 3: %v", err3)
	}

	if !valid1 {
		t.Fatalf("signature 1 is invalid")
	}

	if !valid2 {
		t.Fatalf("signature 2 is invalid")
	}

	if !valid3 {
		t.Fatalf("signature 3 is invalid")
	}

	t.Logf("Signatures Verified Successfully\n")

	pubKeyBytes1 := utils.SerializeCompressed(&pk1.PublicKey)
	signer1, _ := xrpl.ConstructSignerItem(addr1, sig1, pubKeyBytes1)
	pubKeyBytes2 := utils.SerializeCompressed(&pk2.PublicKey)
	signer2, _ := xrpl.ConstructSignerItem(addr2, sig2, pubKeyBytes2)
	pubKeyBytes3 := utils.SerializeCompressed(&pk3.PublicKey)
	signer3, _ := xrpl.ConstructSignerItem(addr3, sig3, pubKeyBytes3)

	accAddr1 := signer1.Signer.SigningPubKey.Address()
	if err1 != nil {
		t.Fatalf("error getting address from account 1: %v", err1)
	}

	accAddr2 := signer2.Signer.SigningPubKey.Address()
	if err2 != nil {
		t.Fatalf("error getting address from account 2: %v", err2)
	}

	accAddr3 := signer3.Signer.SigningPubKey.Address()
	if err3 != nil {
		t.Fatalf("error getting address from account 3: %v", err3)
	}

	if accAddr1 != addr1 {
		t.Fatalf("account 1 is invalid: %v", accAddr1)
	}

	if accAddr2 != addr2 {
		t.Fatalf("account 2 is invalid: %v", accAddr2)
	}

	if accAddr3 != addr3 {
		t.Fatalf("account 3 is invalid: %v", accAddr3)
	}

	t.Logf("Account addresses Decoded Successfully\n")
}

func TestDeriveAddress(t *testing.T) {

}

func TestEncodeTransaction(t *testing.T) {

	payment, err := getSampleTransaction()
	if err != nil {
		t.Fatalf("failed to get sample transaction: %v", err)
	}

	addr1 := "rN5N6fJbc8xyViPDeQFMQMpYfVHuxSGV2G"
	encodedTx, err := xrpl.EncodeTransaction(payment, addr1)
	if err != nil {
		t.Fatalf("failed to encode transaction: %v", err)
	}

	str := hex.EncodeToString(encodedTx)
	if str != "534d54001200002200000000240040c75b201b0048bb5361400000000097d3306840000000000003de73008114f1ada4636583e2dd405af86ac98145d180b22f01831496661e656f4e0995fb56e0af6a69846107e0c8cf96661e656f4e0995fb56e0af6a69846107e0c8cf" {
		t.Fatalf("encodedTx: %v\n", str)
	}

	fmt.Printf("Success!\n")
}

func getSampleTransaction() (*xrputils.Payment, error) {
	// Prepared Transaction: {
	// 	TransactionType: 'Payment',
	// 	Account: 'rPp11a5qy4wJRj4di4buquo1Ftao4GLKe8',
	// 	Destination: 'rN5N6fJbc8xyViPDeQFMQMpYfVHuxSGV2G',
	// 	Amount: '9950000',
	// 	SigningPubKey: '',
	// 	Fee: '990',
	// 	Flags: 0,
	// 	NetworkID: undefined,
	// 	Sequence: 4245336,
	// 	LastLedgerSequence: 4766547,
	//   }

	amount := uint64(9950000)
	fee := uint64(990)
	spenderAccount := "rPp11a5qy4wJRj4di4buquo1Ftao4GLKe8"
	destinationAccount := "rN5N6fJbc8xyViPDeQFMQMpYfVHuxSGV2G"
	sequence := uint32(4245339)
	lastLedgerSeq := uint32(4766547)

	payment, err := xrpl.ConstructPaymentTransaction(amount, fee, spenderAccount, destinationAccount, sequence, lastLedgerSeq)
	if err != nil {
		return nil, err
	}

	return payment, nil
}
