package walletutils

import (
	"encoding/json"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	cpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/internal/wallets/backup"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/wallets"
)

type Processor struct {
	pStorage *policy.Storage
	wStorage *wallets.Storage
	node.IdentifierSignerAndDecrypter
}

func NewProcessor(iSAndD node.IdentifierSignerAndDecrypter, policyStorage *policy.Storage, walletsStorage *wallets.Storage) Processor {
	return Processor{
		pStorage:                     policyStorage,
		wStorage:                     walletsStorage,
		IdentifierSignerAndDecrypter: iSAndD,
	}
}

func (p *Processor) KeyGenerate(
	submissionTag types.SubmissionTag,
	dataFixed *instruction.DataFixed,
	_ []hexutil.Bytes,
	_ []common.Address,
	_ *cpolicy.SigningPolicy,
) ([]byte, []byte, error) {
	req, err := wallets.ParseKeyGenerate(dataFixed)
	if err != nil {
		return nil, nil, err
	}

	err = wallets.CheckKeyGenerate(req)
	if err != nil {
		return nil, nil, err
	}

	if submissionTag == types.Threshold {
		key, err := wallets.GenerateNewKey(req)
		if err != nil {
			return nil, nil, err
		}

		err = p.wStorage.Store(key)
		if err != nil {
			return nil, nil, err
		}
	}
	storedWallet, err := p.wStorage.Get(wallets.KeyIDPair{WalletID: req.WalletId, KeyID: req.KeyId})
	if err != nil {
		return nil, nil, err
	}

	existenceProof := wallets.WalletToKeyExistenceProof(storedWallet, p.TeeID())
	existenceProofEncoded, err := structs.Encode(wallet.KeyExistenceStructArg, existenceProof)
	if err != nil {
		return nil, nil, err
	}

	hash := crypto.Keccak256(existenceProofEncoded)
	signature, err := p.Sign(hash)
	if err != nil {
		return nil, nil, err
	}

	signedProof := wallets.SignedKeyExistenceProof{
		KeyExistence: existenceProofEncoded,
		Signature:    signature,
	}

	resultEncoded, err := json.Marshal(signedProof)
	if err != nil {
		return nil, nil, err
	}

	return resultEncoded, nil, nil
}

func (p *Processor) KeyDelete(
	submissionTag types.SubmissionTag,
	dataFixed *instruction.DataFixed,
	_ []hexutil.Bytes,
	_ []common.Address,
	_ *cpolicy.SigningPolicy,
) ([]byte, []byte, error) {
	req, err := wallets.ParseKeyDelete(dataFixed)
	if err != nil {
		return nil, nil, err
	}

	id := wallets.KeyIDPair{WalletID: req.WalletId, KeyID: req.KeyId}

	switch submissionTag {
	case types.Threshold:
		err = p.wStorage.CheckNonce(id, req.Nonce.Uint64())
		if err != nil {
			return nil, nil, err
		}

		p.wStorage.Remove(id)
		p.wStorage.UpdateNonce(id, req.Nonce.Uint64())
	case types.End:

		exists := p.wStorage.WalletExists(id)
		if exists {
			return nil, nil, errors.New("wallet not deleted, still exists")
		}

	default:
		return nil, nil, errors.New("unexpected submission tag")
	}

	return nil, nil, nil
}

func (p *Processor) KeyDataProviderRestore(
	submissionTag types.SubmissionTag,
	dataFixed *instruction.DataFixed,
	variableMessages []hexutil.Bytes,
	signers []common.Address,
	_ *cpolicy.SigningPolicy,
) ([]byte, []byte, error) {
	metadata, nonce, signersBothRoles, err := p.keyDataProviderRestoreCheck(dataFixed, signers)
	if err != nil {
		return nil, nil, err
	}

	backupID := metadata.WalletBackupID
	id := wallets.KeyIDPair{WalletID: backupID.WalletID, KeyID: backupID.KeyID}

	keySplits, status, err := p.processKeySplitMessages(variableMessages, signersBothRoles, backupID)
	if err != nil {
		return nil, nil, err
	}

	recoveredWallet, err := backup.RecoverWallet(keySplits, metadata)
	if err != nil {
		return nil, status, err
	}

	switch submissionTag {
	case types.Threshold:
		if p.wStorage.WalletExists(id) {
			return nil, nil, errors.New("wallet with given wallet id and key id already exists")
		}

		p.wStorage.UpdateNonce(id, nonce)
		err = p.wStorage.Store(recoveredWallet)
		if err != nil {
			return nil, nil, err
		}

		storedWallet, err := p.wStorage.Get(id)
		if err != nil {
			return nil, nil, err
		}

		ep := wallets.WalletToKeyExistenceProof(storedWallet, p.TeeID())
		existenceProofEncoded, err := structs.Encode(wallet.KeyExistenceStructArg, ep)
		if err != nil {
			return nil, nil, err
		}

		hash := crypto.Keccak256(existenceProofEncoded)
		signature, err := p.Sign(hash)
		if err != nil {
			return nil, nil, errors.New("cannot sign existence proof")
		}

		wskep := wallets.SignedKeyExistenceProof{
			KeyExistence: existenceProofEncoded,
			Signature:    signature,
		}

		resultEncoded, err := json.Marshal(wskep)
		if err != nil {
			return nil, nil, err
		}

		return resultEncoded, status, nil

	case types.End:
		exists := p.wStorage.WalletExists(id)
		checkNonce, err := p.wStorage.Nonce(id)
		if !exists {
			return nil, nil, errors.New("wallet does not exists")
		}
		if err != nil {
			return nil, nil, err
		}
		if checkNonce != nonce {
			return nil, nil, errors.New("wallet nonce already changed")
		}

		return nil, status, nil

	default:
		return nil, nil, errors.New("unexpected submission tag")
	}
}
