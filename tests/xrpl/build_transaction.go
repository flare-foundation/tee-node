package xrpl

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	xrputils "github.com/flare-foundation/tee-node/tests/xrpl/utils"
)

// * ==== Constructing, encoding and signing transactions ==== * //

// Takes in the values for a payment transaction and constructs the Payment struct used to encode the transaction
func ConstructPaymentTransaction(
	amount uint64,
	fee uint64,
	spenderAccount string,
	destinationAccount string,
	sequence uint32,
	lastLedgerSeq uint32,
) (*xrputils.Payment, error) {
	amountValue := xrputils.NewAmount(amount)
	feeValue := xrputils.NewValue(fee)
	acc, e0 := GetAccountFromAddress(spenderAccount)
	dest, e1 := GetAccountFromAddress(destinationAccount)

	if e0 != nil || e1 != nil {
		return nil, fmt.Errorf("error creating payment transaction: %v, %v", e0, e1)
	}

	// Note: we need to add this flag for proper encoding, even if it's not used
	zeroFlag := xrputils.TransactionFlag(0)

	// Create base transaction
	base := xrputils.TxBase{
		TransactionType: xrputils.PAYMENT, // Payment transaction type
		Account:         *acc,
		Sequence:        sequence,
		Fee:             *feeValue,
		SigningPubKey:   new(xrputils.PublicKey), // Empty signing pub key
		Flags:           &zeroFlag,
	}

	// Create the Payment transaction
	payment := &xrputils.Payment{
		TxBase:      base,
		Destination: *dest,
		Amount:      *amountValue,
	}

	// Set LastLedgerSequence
	payment.LastLedgerSequence = &lastLedgerSeq

	return payment, nil
}

// Encode a payment transaction and return the encoded bytes
func EncodeTransaction(payment *xrputils.Payment, address string) ([]byte, error) {
	txBytes, err := xrputils.Encode(payment) // false means don't ignore signing fields
	if err != nil {
		return nil, err
	}

	account, err := GetAccountFromAddress(address)
	if err != nil {
		return nil, err
	}
	accountId := account.Bytes()

	// Decode the hex string to bytes
	multisigTxPrefixBytes, err := hex.DecodeString(xrputils.MULTISIG_TX_PREFIX)
	if err != nil {
		return nil, err
	}

	return addPrefixAndSuffix(txBytes, multisigTxPrefixBytes, accountId), nil
}

// Hash a message using SHA-512 and return the first 256 bits
func HashXRPMessage(message []byte) []byte {
	// Create a new SHA-512 hasher
	hasher := sha512.New()

	// Write the message to the hasher
	hasher.Write(message)

	// Get the hash result
	hash := hasher.Sum(nil)

	return hash[:32] // Return the first 256 bits
}

// -------- Helper functions -------- //

// Get the account from an address
func GetAccountFromAddress(address string) (*xrputils.Account, error) {
	decoded, err := xrputils.Base58Decode(address, xrputils.ALPHABET)
	if err != nil {
		return nil, err
	}

	// Extract components
	if len(decoded) != 25 { // Prefix (1) + AccountID (20) + Checksum (4) = 25 bytes
		return nil, fmt.Errorf("invalid data length: %d", len(decoded))
	}

	// typePrefix := decoded[:1]  // First byte is the type prefix

	var account xrputils.Account
	copy(account[:], decoded[1:21]) // Next 20 bytes

	// checksum := decoded[21:]   // Last 4 bytes

	return &account, nil
}

// Helper function to prepend prefix and append suffix
func addPrefixAndSuffix(data []byte, prefix []byte, suffix []byte) []byte {
	// Prepend the prefix and append the suffix to the data
	final := make([]byte, 0, len(prefix)+len(data)+len(suffix))
	final = append(final, prefix...) // Add the prefix
	final = append(final, data...)   // Add the original data
	final = append(final, suffix...) // Add the suffix
	return final
}
