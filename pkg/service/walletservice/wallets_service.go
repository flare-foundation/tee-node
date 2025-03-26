package walletsservice

import (
	"encoding/hex"

	"fmt"
	api "tee-node/api/types"
	"tee-node/pkg/attestation"
	"tee-node/pkg/utils"
	"tee-node/pkg/wallets"
)

func WalletInfo(req *api.WalletInfoRequest) (*api.WalletInfoResponse, error) {
	walletKeyIdPair := wallets.WalletKeyIdPair{WalletId: req.WalletId, KeyId: req.KeyId}
	ethAddress, err := wallets.GetEthAddress(walletKeyIdPair)
	publicKey, err2 := wallets.GetPublicKey(walletKeyIdPair)
	if err != nil || err2 != nil {
		return nil, fmt.Errorf("wallet non-existent")
	}

	xrpAddress, err := wallets.GetXrpAddress(walletKeyIdPair)
	sec1PubKey := hex.EncodeToString(utils.SerializeCompressed(publicKey))
	if err != nil {
		return nil, fmt.Errorf("wallet non-existent")
	}

	nonces := []string{req.Challenge, "WalletInfo", ethAddress, xrpAddress}

	var tokenBytes []byte
	tokenBytes, err = attestation.GetGoogleAttestationToken(nonces, attestation.OIDCTokenType)
	if err != nil {
		return nil, err
	}

	return &api.WalletInfoResponse{
		EthAddress: ethAddress,
		EthPublicKey: api.ECDSAPublicKey{
			X: publicKey.X.String(),
			Y: publicKey.Y.String(),
		},
		XrpAddress:   xrpAddress,
		XrpPublicKey: sec1PubKey,
		Token:        string(tokenBytes),
	}, nil
}
