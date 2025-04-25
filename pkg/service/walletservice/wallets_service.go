package walletsservice

import (
	"encoding/hex"
	"encoding/json"

	api "tee-node/api/types"
	"tee-node/pkg/attestation"
	"tee-node/pkg/config"
	"tee-node/pkg/policy"
	"tee-node/pkg/utils"
	"tee-node/pkg/wallets"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/pkg/errors"
)

// WalletInfo retrieves information about a specific wallet.
// Parameters:
// - req: Contains the request data for wallet information.
//   - WalletId: The ID of the wallet to retrieve information for.
//   - KeyId: The key ID associated with the wallet.
//   - Challenge: A challenge string for attestation.
func WalletInfo(req *api.WalletInfoRequest) (*api.WalletInfoResponse, error) {
	walletKeyIdPair := wallets.WalletKeyIdPair{WalletId: req.WalletId, KeyId: req.KeyId}
	ethAddress, err := wallets.GetEthAddress(walletKeyIdPair)
	publicKey, err2 := wallets.GetPublicKey(walletKeyIdPair)
	if err != nil || err2 != nil {
		return nil, errors.New("wallet non-existent")
	}

	xrpAddress, err := wallets.GetXrpAddress(walletKeyIdPair)
	sec1PubKey := hex.EncodeToString(utils.SerializeCompressed(publicKey))
	if err != nil {
		return nil, errors.New("wallet non-existent")
	}

	nonces := []string{req.Challenge, "WalletInfo", ethAddress, xrpAddress}

	var tokenBytes []byte
	tokenBytes, err = attestation.GetGoogleAttestationToken(nonces, attestation.OIDCTokenType)
	if err != nil {
		return nil, err
	}

	return &api.WalletInfoResponse{
		EthAddress:   ethAddress,
		PublicKey:    api.PubKeyToBytes(publicKey),
		XrpAddress:   xrpAddress,
		XrpPublicKey: sec1PubKey,
		Token:        string(tokenBytes),
	}, nil
}

func WalletGetBackupPackage(req *api.WalletGetBackupRequest) (*api.WalletGetBackupResponse, error) {
	walletBackupId, err := BackupRequestToBackupId(&req.ITeeWalletBackupManagerKeyDataProviderRestore)
	if err != nil {
		return nil, err
	}

	walletBackup, err := wallets.GetBackup(walletBackupId)
	if err != nil {
		return nil, err
	}
	walletBackupBytes, err := json.Marshal(walletBackup)
	if err != nil {
		return nil, err
	}

	nonces := []string{req.Challenge}
	var tokenBytes []byte
	tokenBytes, err = attestation.GetGoogleAttestationToken(nonces, attestation.OIDCTokenType)
	if err != nil {
		return nil, err
	}

	return &api.WalletGetBackupResponse{WalletBackup: walletBackupBytes, Token: string(tokenBytes)}, nil
}

func WalletUploadBackupPackage(req *api.WalletUploadBackupRequest) (*api.WalletUploadBackupResponse, error) {
	var walletBackup wallets.WalletBackup
	err := json.Unmarshal(req.WalletBackup, &walletBackup)
	if err != nil {
		return nil, err
	}

	err = walletBackup.Check()
	if err != nil {
		return nil, err
	}

	hash, err := walletBackup.HashForSigning()
	if err != nil {
		return nil, err
	}
	walletPubKey, err := api.ParsePubKey(walletBackup.PublicKey)
	if err != nil {
		return nil, err
	}
	err = utils.VerifySignature(hash[:], walletBackup.Signature, crypto.PubkeyToAddress(*walletPubKey))
	if err != nil {
		return nil, err
	}

	err = wallets.StorePendingBackup(&walletBackup) // this also checks
	if err != nil {
		return nil, err
	}

	nonces := []string{req.Challenge}
	var tokenBytes []byte
	tokenBytes, err = attestation.GetGoogleAttestationToken(nonces, attestation.OIDCTokenType)
	if err != nil {
		return nil, err
	}

	return &api.WalletUploadBackupResponse{Token: string(tokenBytes)}, nil
}

func WalletGetBackupShare(req *api.WalletGetBackupShareRequest) (*api.WalletGetBackupShareResponse, error) {
	walletBackupId, err := BackupRequestToBackupId(&req.ITeeWalletBackupManagerKeyDataProviderRestore)
	if err != nil {
		return nil, err
	}

	walletBackup, err := wallets.GetPendingBackup(walletBackupId)
	if err != nil {
		return nil, err
	}

	adminPos, provPos, err := wallets.GetPositionRole(walletBackup, req.OwnerPublicKey)
	if err != nil {
		return nil, err
	}

	var adminEncryptedWalletSplit []byte
	var providerEncryptedWalletSplit []byte
	if adminPos >= 0 {
		adminEncryptedWalletSplit = walletBackup.AdminEncryptedParts.Splits[adminPos]
	}
	if provPos >= 0 {
		providerEncryptedWalletSplit = walletBackup.ProvidersEncryptedParts.Splits[provPos]
	}

	nonces := []string{req.Challenge}
	var tokenBytes []byte
	tokenBytes, err = attestation.GetGoogleAttestationToken(nonces, attestation.OIDCTokenType)
	if err != nil {
		return nil, err
	}

	return &api.WalletGetBackupShareResponse{AdminEncryptedWalletSplit: adminEncryptedWalletSplit, ProviderEncryptedWalletSplit: providerEncryptedWalletSplit, Token: string(tokenBytes)}, nil
}

func WalletUploadBackupShare(req *api.WalletUploadBackupShareRequest) (*api.WalletUploadBackupShareResponse, error) {
	walletBackupId, err := BackupRequestToBackupId(&req.ITeeWalletBackupManagerKeyDataProviderRestore)
	if err != nil {
		return nil, err
	}

	walletBackup, err := wallets.GetPendingBackup(walletBackupId)
	if err != nil {
		return nil, err
	}

	var keySplit wallets.KeySplit
	err = json.Unmarshal(req.DecryptedWalletSplit, &keySplit)
	if err != nil {
		return nil, err
	}
	if keySplit.WalletBackupId != walletBackupId {
		return nil, errors.New("wallet backup id in the share does not match the given id")
	}

	adminPos, provPos, err := wallets.GetPositionRole(walletBackup, keySplit.OwnerPublicKey)
	if err != nil {
		return nil, err
	}

	err = keySplit.VerifySignature()
	if err != nil {
		return nil, err
	}

	err = wallets.CheckPendingBackupSplitStorage(&keySplit, req.IsAdmin)
	if err != nil {
		return nil, err
	}
	if adminPos >= 0 && req.IsAdmin {
		wallets.StorePendingBackupAdminSplit(&keySplit)
	}
	if provPos >= 0 && !req.IsAdmin {
		wallets.StorePendingBackupProviderSplit(&keySplit)
	}

	thresholdReached, err := wallets.IsPendingBackupThresholdReached(walletBackupId)
	if err != nil {
		return nil, err
	}

	if thresholdReached {
		wallet, err := wallets.PendingWalletBackupRecover(walletBackupId)
		if err != nil {
			return nil, err
		}

		activePolicy := policy.GetActiveSigningPolicy()
		pubKeysMap := policy.GetActiveSigningPolicyPublicKeysMap()
		activePolicyPublicKeys, err := policy.GetSigningPolicyPublicKeys(activePolicy, pubKeysMap)
		if err != nil {
			return nil, err
		}
		normalizedWeights := config.WeightsNormalization(activePolicy.Weights)

		walletBackup, err := wallets.BackupWallet(wallet, activePolicyPublicKeys, config.DataProvidersBackupThreshold, normalizedWeights, activePolicy.RewardEpochId)
		if err != nil {
			return nil, err
		}

		err = wallets.StoreWallet(wallet)
		if err != nil {
			return nil, err
		}
		wallets.StoreBackup(walletBackup)

		wallets.RemovePendingBackup(walletBackupId)
	}

	nonces := []string{req.Challenge}
	var tokenBytes []byte
	tokenBytes, err = attestation.GetGoogleAttestationToken(nonces, attestation.OIDCTokenType)
	if err != nil {
		return nil, err
	}

	return &api.WalletUploadBackupShareResponse{Token: string(tokenBytes)}, nil
}

func BackupRequestToBackupId(req *wallet.ITeeWalletBackupManagerKeyDataProviderRestore) (wallets.WalletBackupId, error) {
	if req.RewardEpochId == nil {
		return wallets.WalletBackupId{}, errors.New("reward epoch not given")
	}

	walletBackupId := wallets.WalletBackupId{
		TeeId:         req.TeeId,
		WalletId:      req.WalletId,
		KeyId:         req.KeyId,
		OpType:        req.OpType,
		RewardEpochID: uint32(req.RewardEpochId.Uint64()),
	}
	if len(req.PublicKey) != 64 {
		return wallets.WalletBackupId{}, errors.New("unsupported public key format")
	}
	copy(walletBackupId.PublicKey.X[:], req.PublicKey[:32])
	copy(walletBackupId.PublicKey.Y[:], req.PublicKey[32:])

	return walletBackupId, nil
}
