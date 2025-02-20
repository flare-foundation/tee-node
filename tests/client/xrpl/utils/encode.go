package utils

func Encode(payment *Payment) ([]byte, error) {
	// Order of encoding
	// 1. Transaction Type
	// 2. Sequence
	// 3. LastLedgerSequence
	// 4. Amount
	// 5. Fee
	// 6. SigningPubKey
	// 7. Account
	// 8. Destination

	// Each field is encoded as follows:
	// 1. First the encoding (1 byte type, 1 byte field), see constants.go for the encodings
	// 2. Then the value of the field to the encoding

	var encoding []byte = make([]byte, 0)

	// 1. Transaction Type  -------------------------
	enc := reverseEncodings["TransactionType"]
	encBytes := EncToBytes(enc)
	encoding = append(encoding, encBytes...)

	txTypeBytes, err := toBytes(payment.TransactionType)
	if err != nil {
		return nil, err
	}
	encoding = append(encoding, txTypeBytes...)

	// 2. Sequence  --------------------------------
	enc = reverseEncodings["Flags"]
	encBytes = EncToBytes(enc)
	encoding = append(encoding, encBytes...)

	flagsBytes, err := toBytes(payment.Flags)
	if err != nil {
		return nil, err
	}
	encoding = append(encoding, flagsBytes...)

	// 2. Sequence  --------------------------------
	enc = reverseEncodings["Sequence"]
	encBytes = EncToBytes(enc)
	encoding = append(encoding, encBytes...)

	sequenceBytes, err := toBytes(payment.Sequence)
	if err != nil {
		return nil, err
	}
	encoding = append(encoding, sequenceBytes...)

	// 3. LastLedgerSequence  ----------------------
	enc = reverseEncodings["LastLedgerSequence"]
	encBytes = EncToBytes(enc)
	encoding = append(encoding, encBytes...)

	llsBytes, err := toBytes(payment.LastLedgerSequence)
	if err != nil {
		return nil, err
	}
	encoding = append(encoding, llsBytes...)

	// 4. Amount  ----------------------------------
	enc = reverseEncodings["Amount"]
	encBytes = EncToBytes(enc)
	encoding = append(encoding, encBytes...)

	amountBytes, err := toBytes(payment.Amount.Bytes())
	if err != nil {
		return nil, err
	}
	encoding = append(encoding, amountBytes...)

	// 5. Fee  -------------------------------------
	enc = reverseEncodings["Fee"]
	encBytes = EncToBytes(enc)
	encoding = append(encoding, encBytes...)

	feeBytes, err := toBytes(payment.Fee.Bytes())
	if err != nil {
		return nil, err
	}
	encoding = append(encoding, feeBytes...)

	// 6. SigningPubKey  ---------------------------
	enc = reverseEncodings["SigningPubKey"]
	encBytes = EncToBytes(enc)
	encoding = append(encoding, encBytes...)

	pkBytes, err := payment.SigningPubKey.Marshal()
	if err != nil {
		return nil, err
	}
	encoding = append(encoding, pkBytes...)

	// 7. Account  ---------------------------------
	enc = reverseEncodings["Account"]
	encBytes = EncToBytes(enc)
	encoding = append(encoding, encBytes...)

	accBytes, err := payment.Account.Marshal()
	if err != nil {
		return nil, err
	}
	encoding = append(encoding, accBytes...)

	// 8. Destination
	enc = reverseEncodings["Destination"]
	encBytes = EncToBytes(enc)
	encoding = append(encoding, encBytes...)

	destBytes, err := payment.Destination.Marshal()
	if err != nil {
		return nil, err
	}
	encoding = append(encoding, destBytes...)

	return encoding, nil
}

// Note: Do we need this?
// func Decode(paymentEncoding []byte) (*Payment, error) {
// }
