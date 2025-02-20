package xrpl

import (
	"fmt"
	xrputils "tee-node/tests/client/xrpl/utils"
)

func ConstructSignerItem(_account string, txnSignature []byte, pkBytes []byte) (*xrputils.Signer, error) {

	account, e1 := GetAccountFromAddress(_account)
	if e1 != nil {
		return nil, fmt.Errorf("error creating payment transaction: %v", e1)
	}

	// txnSignature := xrputils.VariableLength(_txnSignature)

	var pubKey xrputils.PublicKey
	copy(pubKey[:], pkBytes)

	signerItem := &xrputils.SignerItem{
		Account:       *account,
		TxnSignature:  txnSignature,
		SigningPubKey: &pubKey,
	}

	signer := &xrputils.Signer{
		Signer: *signerItem,
	}

	return signer, nil
}

// The SignerItem is in a format used for encoding the transaction
// This function deconstructs the SignerItem into its components in a more useful format (string address, []byte txnSignature, string pubKey)
func DeconstructSignerItem(signer *xrputils.SignerItem) (string, []byte, []byte, error) {
	signerAddress := signer.SigningPubKey.Address()

	return signerAddress, signer.TxnSignature, signer.SigningPubKey.Bytes(), nil
}
