package wallets

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"sync"
	api "tee-node/api/types"
	"tee-node/pkg/attestation"
	"tee-node/pkg/config"
	"tee-node/pkg/node"
	"tee-node/pkg/requests"
	"tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/nacl/box"
)

var backupWalletsStorage = InitBackupWalletsStorage()

// BackupWalletsStorage is a structure that holds wallet shares for backup purposes.
type BackupWalletsStorage struct {
	// Storage maps a combination of BackupId, WalletId, and KeyId to a map of share IDs to WalletShares.
	Storage map[string]map[string]WalletShare

	sync.Mutex
}

// BackupWalletKeyIdTriple is a struct used to uniquely identify a wallet backup.
type BackupWalletKeyIdTriple struct {
	BackupId *big.Int
	WalletId common.Hash
	KeyId    *big.Int
}

func (b *BackupWalletKeyIdTriple) Id() string {
	return fmt.Sprintf("%v:%v:%v", b.BackupId.String(), b.WalletId.Hex(), b.KeyId.String())
}

func InitBackupWalletsStorage() BackupWalletsStorage {
	return BackupWalletsStorage{Storage: make(map[string]map[string]WalletShare)}
}

type AttestationRequest struct {
	Nonce  string
	NodeId string // todo: it should be signed by data providers
}

type AttestationResponse struct {
	Token string
	Nonce string
}

// SendShare sends a wallet share to another node over a WebSocket connection.
// Parameters:
// - conn: The WebSocket connection to use for sending the share.
// - share: The WalletShare to be sent.
// - outNodeId: The ID of the node receiving the share.
// - pubKey: The public key of the receiving node.
// - instructionData: The instruction data associated with the share.
// - signatures: Digital signatures for the operation.
// todo: Add instruction and signatures check also by receiving nodes? at least code version of the receiving nodes?
func SendShare(conn *websocket.Conn, share *WalletShare, outNodeId, outPubKey string, instructionData *instruction.DataFixed, signatures [][]byte) error {
	myNode := node.GetNodeId()

	err := StartMutualAttestation(conn, myNode.Id.Hex(), outNodeId)
	if err != nil {
		return err
	}

	shareBytes, err := json.Marshal(share)
	if err != nil {
		return err
	}

	pubKeyBytes, err := hex.DecodeString(outPubKey)
	if err != nil {
		return err
	}
	pk := [32]byte(pubKeyBytes)

	encrypted, err := box.SealAnonymous(nil, shareBytes, &pk, rand.Reader)
	if err != nil {
		return err
	}

	err = conn.WriteMessage(websocket.TextMessage, encrypted)
	if err != nil {
		return err
	}

	logger.Infof("sent a share for wallet %s", share.WalletId)

	return err
}

// GetShares receives wallet shares from another node over a WebSocket connection.
// Parameters:
// - conn: The WebSocket connection to use for receiving the shares.
func GetShares(conn *websocket.Conn) error {
	myNode := node.GetNodeId()

	_, err := ReceiveMutualAttestation(conn, myNode.Id.Hex())
	if err != nil {
		return err
	}

	_, encryptedMsg, err := conn.ReadMessage()
	if err != nil {
		return err
	}

	shareBytes, ok := box.OpenAnonymous(nil, encryptedMsg, &myNode.EncryptionKey.PublicKey, &myNode.EncryptionKey.PrivateKey)
	if !ok {
		return errors.New("decryption failed")
	}

	walletShare := WalletShare{}
	err = json.Unmarshal(shareBytes, &walletShare)
	if err != nil {
		return err
	}

	backupIdTriple := BackupWalletKeyIdTriple{WalletId: walletShare.WalletId, KeyId: walletShare.KeyId, BackupId: walletShare.BackupId}

	backupWalletsStorage.Lock()
	defer backupWalletsStorage.Unlock()
	if _, ok := backupWalletsStorage.Storage[backupIdTriple.Id()]; !ok {
		backupWalletsStorage.Storage[backupIdTriple.Id()] = make(map[string]WalletShare)
	}
	backupWalletsStorage.Storage[backupIdTriple.Id()][walletShare.Share.ID()] = walletShare
	logger.Infof("received a share for wallet %s, id %s", walletShare.WalletId, walletShare.Share.ID())

	return nil
}

// recoverShareRequest contains information about a recover share request.
type recoverShareRequest struct {
	I               int                   // index of the share
	InstructionData instruction.DataFixed // Todo: Explain this
	Signatures      [][]byte
}

// Check verifies the validity of a share request.
// Parameters:
// - myNodeId: The ID of the current node.
// - outNodeId: The ID of the node that sent the request.
func (s recoverShareRequest) Check(myNodeId, outNodeId string) error {
	instructionData := &instruction.Data{DataFixed: s.InstructionData, AdditionalVariableMessage: []byte("")} // variable part is empty

	requestCounter := requests.NewRequestCounter(instructionData, common.Address{}, config.Thresholds[utils.OpHashToString(instructionData.OPType)][utils.OpHashToString(instructionData.OPCommand)])
	for _, signature := range s.Signatures {
		providerAddress, err := requests.CheckSignature(instructionData, signature, requestCounter.RequestPolicy)
		if err != nil {
			return err
		}
		requestCounter.AddRequestSignature(providerAddress, signature)
	}

	thresholdReached := requestCounter.ThresholdReached()
	if !thresholdReached {
		return errors.New("threshold not reached")
	}

	if outNodeId != s.InstructionData.TeeID.String() {
		return errors.New("Requester's NodeId not matching instructions")
	}

	recoverWalletRequest, err := api.NewRecoverWalletRequest(&s.InstructionData)
	if err != nil {
		return err
	}
	if recoverWalletRequest.BackupTeeMachines[s.I].TeeId.String() != myNodeId {
		return errors.New("My NodeId not matching instructions")
	}

	return nil
}

// Extract extracts key information from a recover share request.
// Returns:
// - A BackupWalletKeyIdTriple identifying the wallet backup.
// - The share ID.
// - The public key as a string.
func (s recoverShareRequest) Extract() (BackupWalletKeyIdTriple, string, string) {
	recoverWalletRequest, _ := api.NewRecoverWalletRequest(&s.InstructionData) // error is already checked before
	var additionalFixedMessage api.RecoverWalletRequestAdditionalFixedMessage
	err := json.Unmarshal(s.InstructionData.AdditionalFixedMessage, &additionalFixedMessage)
	if err != nil {
		logger.Errorf("error unmarshalling additionalFixedMessage: %s", err)
	}

	return BackupWalletKeyIdTriple{
			BackupId: recoverWalletRequest.BackupId,
			WalletId: recoverWalletRequest.WalletId,
			KeyId:    recoverWalletRequest.KeyId,
		},
		additionalFixedMessage.ShareIds[s.I],
		hex.EncodeToString(recoverWalletRequest.PublicKey[:])

}

// RequestShare requests a wallet share from another node over a WebSocket connection.
// Parameters:
// - conn: The WebSocket connection to use for the request.
// - outNodeId: The ID of the node to request the share from.
// - i: The index of the share to request.
// - instructionData: The instruction data associated with the request.
// - signatures: Digital signatures for the operation.
func RequestShare(conn *websocket.Conn, outNodeId common.Address, i int, instructionData *instruction.DataFixed, signatures [][]byte) (*WalletShare, error) {
	myNode := node.GetNodeId()

	err := StartMutualAttestation(conn, myNode.Id.Hex(), outNodeId.Hex())
	if err != nil {
		return nil, err
	}

	shareReq := recoverShareRequest{
		I:               i,
		InstructionData: *instructionData,
		Signatures:      signatures,
	}
	err = conn.WriteJSON(shareReq)
	if err != nil {
		return nil, err
	}

	_, encryptedMsg, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	shareBytes, ok := box.OpenAnonymous(nil, encryptedMsg, &myNode.EncryptionKey.PublicKey, &myNode.EncryptionKey.PrivateKey)
	if !ok {
		return nil, err
	}

	walletShare := WalletShare{}
	err = json.Unmarshal(shareBytes, &walletShare)
	if err != nil {
		return nil, err
	}

	return &walletShare, nil
}

// RecoverShare processes a request to recover a wallet share over a WebSocket connection.
// (Called by the receiving node in the RequestShare function)
// Parameters:
// - conn: The WebSocket connection to use for the recovery.
func RecoverShare(conn *websocket.Conn) error {
	myNode := node.GetNodeId()

	outNodeId, err := ReceiveMutualAttestation(conn, myNode.Id.Hex())
	if err != nil {
		return err
	}

	var shareReq recoverShareRequest
	err = conn.ReadJSON(&shareReq)
	if err != nil {
		return err
	}

	err = shareReq.Check(myNode.Id.Hex(), outNodeId)
	if err != nil {
		return err
	}
	backupIdTriple, shareId, pubKey := shareReq.Extract()

	backupWalletsStorage.Lock()
	defer backupWalletsStorage.Unlock()
	walletShares, ok := backupWalletsStorage.Storage[backupIdTriple.Id()]
	if !ok {
		return errors.New("no backup share of wallet with given name")
	}
	walletShare, ok := walletShares[shareId]
	if !ok {
		return errors.New("no backup share of wallet with given Id")
	}

	shareBytes, err := json.Marshal(walletShare)
	if err != nil {
		return err
	}
	pubKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return err
	}
	pk := [32]byte(pubKeyBytes)

	encrypted, err := box.SealAnonymous(nil, shareBytes, &pk, rand.Reader)
	if err != nil {
		return err
	}

	err = conn.WriteMessage(websocket.TextMessage, encrypted)
	if err != nil {
		return err
	}

	logger.Infof("provided a share for wallet %s", walletShare.WalletId)

	return nil
}

// StartMutualAttestation initiates a mutual attestation process with another node.
// Parameters:
// - conn: The WebSocket connection to use for the attestation.
// - myNodeId: The ID of the current node.
// - outNodeId: The ID of the node to attest with.
func StartMutualAttestation(conn *websocket.Conn, myNodeId, outNodeId string) error {
	nonce := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return fmt.Errorf("failed to create nonce: %w", err)
	}
	err = conn.WriteJSON(AttestationRequest{Nonce: string(nonce), NodeId: myNodeId})
	if err != nil {
		return err
	}

	attResp := AttestationResponse{}
	err = conn.ReadJSON(&attResp)
	if err != nil {
		return err
	}
	token, err := attestation.ValidatePKIToken(attestation.GoogleCert, attResp.Token)
	if err != nil {
		return err
	}

	ok, err := attestation.ValidateClaims(token, []string{string(nonce), outNodeId})
	if !ok {
		return err
	}

	tokenBytes, err := attestation.GetGoogleAttestationToken([]string{attResp.Nonce, myNodeId}, attestation.PKITokenType)
	if err != nil {
		return err
	}

	err = conn.WriteJSON(AttestationResponse{Token: string(tokenBytes)})
	if err != nil {
		return err
	}

	return nil
}

// ReceiveMutualAttestation completes a mutual attestation process with another node.
// Parameters:
// - conn: The WebSocket connection to use for the attestation.
// - myId: The ID of the current node.
// Returns:
// - The ID of the node that initiated the attestation.
func ReceiveMutualAttestation(conn *websocket.Conn, myId string) (string, error) {
	attReq := AttestationRequest{}
	err := conn.ReadJSON(&attReq)
	if err != nil {
		return "", err
	}

	tokenBytes, err := attestation.GetGoogleAttestationToken([]string{attReq.Nonce, myId}, attestation.PKITokenType)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}
	err = conn.WriteJSON(&AttestationResponse{Token: string(tokenBytes), Nonce: string(nonce)})
	if err != nil {
		return "", err
	}

	attResp := AttestationResponse{}
	err = conn.ReadJSON(&attResp)
	if err != nil {
		return "", err
	}
	token, err := attestation.ValidatePKIToken(attestation.GoogleCert, attResp.Token)
	if err != nil {
		return "", err
	}
	ok, err := attestation.ValidateClaims(token, []string{string(nonce), attReq.NodeId})
	if !ok {
		return "", errors.Errorf("fail of validate %s", err)
	}

	return attReq.NodeId, nil
}
