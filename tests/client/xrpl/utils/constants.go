package utils

import "strings"

const ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
const MULTISIG_TX_PREFIX = "534d5400"

const PAYMENT TransactionType = 0

const (
	ST_UINT16  uint8 = 1
	ST_UINT32  uint8 = 2
	ST_AMOUNT  uint8 = 6
	ST_VL      uint8 = 7
	ST_ACCOUNT uint8 = 8
	ST_OBJECT  uint8 = 14
	ST_ARRAY   uint8 = 15
)

// See rippled's SField.cpp for the strings and corresponding encoding values.
var encodings = map[enc]string{
	// 16-bit unsigned integers (common)
	{ST_UINT16, 2}: "TransactionType",
	// 16-bit unsigned integers (uncommon)
	// 32-bit unsigned integers (common)
	{ST_UINT32, 1}:  "NetworkID",
	{ST_UINT32, 2}:  "Flags",
	{ST_UINT32, 3}:  "SourceTag",
	{ST_UINT32, 4}:  "Sequence",
	{ST_UINT32, 10}: "Expiration",
	{ST_UINT32, 14}: "DestinationTag",
	// 32-bit unsigned integers (uncommon)
	{ST_UINT32, 27}: "LastLedgerSequence",
	// currency amount (common)
	{ST_AMOUNT, 1}: "Amount",
	{ST_AMOUNT, 8}: "Fee",
	// variable length (common)
	{ST_VL, 3}: "SigningPubKey",
	{ST_VL, 4}: "TxnSignature",
	{ST_VL, 6}: "Signature",
	// account (common)
	{ST_ACCOUNT, 1}: "Account",
	{ST_ACCOUNT, 3}: "Destination",
}

var reverseEncodings map[string]enc
var signingFields map[enc]struct{}

func init() {
	reverseEncodings = make(map[string]enc)
	signingFields = make(map[enc]struct{})
	for e, name := range encodings {
		reverseEncodings[name] = e
		if strings.Contains(name, "Signature") {
			signingFields[e] = struct{}{}
		}
	}
}
