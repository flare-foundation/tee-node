package walletutils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	pkgbackup "github.com/flare-foundation/tee-node/pkg/wallets/backup"

	"github.com/flare-foundation/tee-node/pkg/processorutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/flare-foundation/tee-node/pkg/wallets"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
)

// keyRestoreDataCheck checks the following:
//
//   - the teeID in the instruction data matches the teeID of the current TEE
//   - the signing algorithm is supported
//   - the wallet backup ID in the metadata matches the ID in the instruction data
//   - the backup's reward epoch is at most one epoch ahead of the
//     instruction's (quorum-signed) reward epoch
//   - the cosigners and cosigner threshold stated in the instruction match the
//     admin addresses and admin threshold in the backup data
//
// and returns backup metadata, action nonce, and error.
//
// The signing policy of the backup's reward epoch is deliberately not
// consulted, so backups stay restorable on nodes that never held that policy.
// The instruction pipeline separately requires a majority of the current
// policy's data-provider weight among signers (processorutils.CheckThresholds).
// Provider participation is enforced cryptographically at reconstruction:
// each key split is signed by the wallet key and was ECIES-encrypted to its
// holder, so possession of a decrypted split is the credential, regardless of
// which signer couriers it.
func (p *Processor) keyRestoreDataCheck(
	instructionData *instruction.DataFixed,
	teeID common.Address,
) (*pkgbackup.WalletBackupMetaData, uint64, error) {
	restoreRequest, err := wallets.ParseKeyDataProviderRestore(instructionData)
	if err != nil {
		return nil, 0, err
	}

	teePubKey, err := types.ParsePubKey(types.PublicKey{
		X: restoreRequest.TeePublicKey.X,
		Y: restoreRequest.TeePublicKey.Y,
	})
	if err != nil {
		return nil, 0, err
	}
	if crypto.PubkeyToAddress(*teePubKey) != teeID {
		return nil, 0, errors.New("teeID does not match given public key")
	}
	if !slices.Contains(wallets.Algos, restoreRequest.BackupId.SigningAlgo) {
		return nil, 0, errors.New("signing algorithm not supported")
	}

	var backupMetadata pkgbackup.WalletBackupMetaData
	err = json.Unmarshal(instructionData.AdditionalFixedMessage, &backupMetadata)
	if err != nil {
		return nil, 0, err
	}
	if err := wallets.ValidateWalletMemberCounts(len(backupMetadata.AdminsPublicKeys), len(backupMetadata.Cosigners)); err != nil {
		return nil, 0, err
	}

	backupID, err := backupRequestToID(&restoreRequest)
	if err != nil {
		return nil, 0, err
	}
	if err = backupMetadata.WalletBackupID.Equal(&backupID); err != nil { //nolint:staticcheck // to avoid confusion we do not call backupMetadata.Equal
		return nil, 0, err
	}

	if uint64(backupID.RewardEpochID) > uint64(instructionData.RewardEpochID)+1 {
		return nil, 0, fmt.Errorf("backup reward epoch %d is in the future of instruction reward epoch %d",
			backupID.RewardEpochID, instructionData.RewardEpochID)
	}

	adminAddresses, err := utils.PubKeysToAddresses(backupMetadata.AdminsPublicKeys)
	if err != nil {
		return nil, 0, err
	}

	if utils.HasDuplicateAddresses(adminAddresses) {
		return nil, 0, errors.New("backup metadata contains duplicate admin addresses")
	}

	err = processorutils.CheckMatchingCosigners(instructionData.Cosigners, adminAddresses, instructionData.CosignersThreshold, backupMetadata.AdminsThreshold)
	if err != nil {
		return nil, 0, err
	}

	if !restoreRequest.Nonce.IsUint64() {
		return nil, 0, errors.New("nonce too large")
	}

	keyActionNonce := restoreRequest.Nonce.Uint64()

	return &backupMetadata, keyActionNonce, nil
}

// backupRequestToID constructs wallet backup ID from the restore request.
func backupRequestToID(req *wallet.IWalletBackupManagerKeyDataProviderRestore) (wallets.WalletBackupID, error) {
	if len(req.BackupId.PublicKey) != 64 {
		return wallets.WalletBackupID{}, errors.New("unsupported public key format")
	}

	backupID := wallets.WalletBackupID{
		TeeID:         req.BackupId.TeeId,
		WalletID:      req.BackupId.WalletId,
		KeyID:         req.BackupId.KeyId,
		KeyType:       req.BackupId.KeyType,
		SigningAlgo:   req.BackupId.SigningAlgo,
		PublicKey:     append(make([]byte, 0, len(req.BackupId.PublicKey)), req.BackupId.PublicKey...),
		RewardEpochID: req.BackupId.RewardEpochId,
		RandomNonce:   req.BackupId.RandomNonce,
	}

	return backupID, nil
}

func (p *Processor) processKeySplitMessages(variableMessages []hexutil.Bytes, walletBackupId wallets.WalletBackupID) ([]*pkgbackup.KeySplit, []byte, error) {
	chainID, err := p.ChainID()
	if err != nil {
		return nil, nil, err
	}

	allKeySplits := make([]*pkgbackup.KeySplit, 0)
	duplicateCheck := make(map[common.Hash]int)

	restoreStatus := wallets.NewKeyDataProviderRestoreResultStatus()

	for i, keySplitMessage := range variableMessages {
		keySplitsPlaintext, err := p.Decrypt(keySplitMessage)
		if err != nil {
			restoreStatus.AddError(i, err)
			continue
		}

		keySplits, err := processKeySplitPlaintext(keySplitsPlaintext, walletBackupId, chainID)
		if err != nil {
			restoreStatus.AddError(i, err)
			continue
		}

		for _, keySplit := range keySplits {
			keySplitHash, err := keySplit.HashForSigning()
			if err != nil {
				restoreStatus.AddError(i, err)
				continue
			}
			if _, ok := duplicateCheck[keySplitHash]; ok {
				err = errors.New("duplicate key split")
				restoreStatus.AddError(i, err)
				continue
			}
			duplicateCheck[keySplitHash] = i

			allKeySplits = append(allKeySplits, keySplit)
		}
	}

	if !restoreStatus.Empty() {
		logger.Warnf("errors in restore process: %v", restoreStatus)
	}

	resultStatus, err := json.Marshal(restoreStatus)
	if err != nil {
		return nil, nil, err
	}

	return allKeySplits, resultStatus, nil
}

// maxKeySplitsPerMessage bounds the number of key splits accepted from a
// single signer's variable message. An entity holds at most two splits: a
// provider split and, if it is also an admin, an admin split.
const maxKeySplitsPerMessage = 2

// processKeySplitPlaintext decodes plaintext to a slice of KeySplits and validates them.
//
// The plaintext is either a single JSON-encoded KeySplit or a JSON array of at
// most maxKeySplitsPerMessage KeySplits. Splits are classified as admin or
// provider downstream by their IsAdmin flag, which is covered by the wallet-key
// signature verified here, together with the expected backupID.
func processKeySplitPlaintext(plaintext []byte, walletBackupID wallets.WalletBackupID, chainID uint64) ([]*pkgbackup.KeySplit, error) {
	keySplits := make([]*pkgbackup.KeySplit, 0, maxKeySplitsPerMessage)

	// A JSON document's top-level type is determined by its first
	// non-whitespace byte (RFC 8259; the trim set is exactly JSON's
	// whitespace), so this dispatch is exact: any input it misroutes is
	// invalid JSON and fails to unmarshal in either branch.
	trimmed := bytes.TrimLeft(plaintext, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var decoded []pkgbackup.KeySplit
		if err := json.Unmarshal(plaintext, &decoded); err != nil {
			return nil, err
		}
		if len(decoded) == 0 || len(decoded) > maxKeySplitsPerMessage {
			return nil, fmt.Errorf("expected between 1 and %d key splits, got %d", maxKeySplitsPerMessage, len(decoded))
		}
		for i := range decoded {
			keySplits = append(keySplits, &decoded[i])
		}
	} else {
		var keySplit pkgbackup.KeySplit
		if err := json.Unmarshal(plaintext, &keySplit); err != nil {
			return nil, err
		}
		keySplits = append(keySplits, &keySplit)
	}

	for _, keySplit := range keySplits {
		if keySplit.WalletBackupID.Equal(&walletBackupID) != nil {
			return nil, errors.New("wallet backup id in the share does not match the id in the key split")
		}

		if err := keySplit.VerifySignature(chainID); err != nil {
			return nil, err
		}
	}

	return keySplits, nil
}
