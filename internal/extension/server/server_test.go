package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/hash"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/wallets"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/stretchr/testify/require"
)

func setupTestServer(t *testing.T, proxyPort int, port int) *ExtenderServer {
	testNode, err := node.Initialize(node.ZeroState{})
	require.NoError(t, err)

	wStorage := wallets.InitializeStorage()

	proxyURL := settings.ProxyURLMutex{
		URL: "http://localhost:" + strconv.Itoa(proxyPort),
	}

	// Create test server
	server := NewExtenderServer(port, testNode, wStorage, &proxyURL)

	return server
}

func setupTestWallet(t *testing.T, ws *wallets.Storage, signingAlgo common.Hash) *wallets.Wallet {
	// Generate a test private key
	privateKey, err := wallets.GenerateKey(signingAlgo)
	require.NoError(t, err)

	seed := crypto.Keccak256(privateKey, []byte("random"))
	require.NoError(t, err)

	// Create test wallet
	walletID := crypto.Keccak256Hash(seed)
	keyID := uint64(0)

	wallet := &wallets.Wallet{
		WalletID:    walletID,
		KeyID:       keyID,
		PrivateKey:  privateKey,
		SigningAlgo: signingAlgo,
		Status: &wallets.WalletStatus{
			Nonce:      0,
			StatusCode: 0,
		},
	}

	// Store wallet in storage
	err = ws.Store(wallet)
	require.NoError(t, err)

	// Verify wallet was stored
	storedWallet, err := ws.Get(wallets.KeyIDPair{WalletID: walletID, KeyID: keyID})
	require.NoError(t, err)
	require.NotNil(t, storedWallet)

	return wallet
}

func TestGetKeyInfoHandler(t *testing.T) {
	port := 8880
	proxyPort := 5507
	extServer := setupTestServer(t, proxyPort, port)
	go extServer.Serve()                        //nolint:errcheck
	defer extServer.Close(context.Background()) //nolint:errcheck

	testWallet := setupTestWallet(t, extServer.wStorage, wallets.XRPAlgo)
	wID, kID := testWallet.WalletID, testWallet.KeyID
	url := fmt.Sprintf("http://localhost:%d/key-info/%s/%d", port, wID.Hex(), kID)

	// wait for server to start
	time.Sleep(500 * time.Millisecond)

	resp, err := http.Get(url)
	require.NoError(t, err)

	defer resp.Body.Close() //nolint:errcheck

	// Assert response
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var response wallet.ITeeWalletKeyManagerKeyExistence

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&response)
	require.NoError(t, err)

	// Check that the wallet ID and key ID match
	require.Equal(t, wID.Hex(), common.BytesToHash(response.WalletId[:]).Hex())
	require.Equal(t, kID, response.KeyId)
	require.Equal(t, kID, response.KeyId)
}

func TestSignWithKeyHandler(t *testing.T) {
	port := 8881
	proxyPort := 5503
	server := setupTestServer(t, proxyPort, port)
	go server.Serve()                        //nolint:errcheck
	defer server.Close(context.Background()) //nolint:errcheck

	wallet := setupTestWallet(t, server.wStorage, wallets.XRPAlgo)
	wID, kID := wallet.WalletID, wallet.KeyID

	// Create test message
	message := crypto.Keccak256([]byte("test message to sign"))

	// Create request body
	requestBody := types.SignRequest{
		Message: message,
	}

	// wait for server to start
	time.Sleep(500 * time.Millisecond)

	url := fmt.Sprintf("http://localhost:%d/sign/%s/%d", port, wID.Hex(), kID)
	body, err := post(url, requestBody)
	require.NoError(t, err)

	// Parse response
	var response types.SignResponse
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// Verify response structure
	require.Equal(t, message, response.Message)
	require.NotEmpty(t, response.Signature)

	// Verify signature is valid
	signature := response.Signature

	// Verify the signature
	pubKey, err := crypto.SigToPub(hash.Sha512Half(message), signature)
	require.NoError(t, err)
	require.Equal(t, wallets.ToECDSAUnsafe(wallet.PrivateKey).PublicKey, *pubKey)
}

func TestSignWithTeeHandler(t *testing.T) {
	port := 8882
	proxyPort := 5504
	server := setupTestServer(t, proxyPort, port)
	go server.Serve()                        //nolint:errcheck
	defer server.Close(context.Background()) //nolint:errcheck

	// Create test message
	message := []byte("test message to sign with TEE")

	// Create request body
	requestBody := types.SignRequest{
		Message: message,
	}

	// Create request
	url := fmt.Sprintf("http://localhost:%d/sign", port)
	body, err := post(url, requestBody)
	require.NoError(t, err)

	// Parse response
	var response types.SignResponse
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// Verify response structure
	require.Equal(t, message, response.Message)
	require.NotEmpty(t, response.Signature)

	// Verify signature is valid
	signature := response.Signature

	// Verify the signature
	pubKey, err := crypto.SigToPub(accounts.TextHash(crypto.Keccak256(message)), signature)
	require.NoError(t, err)
	expectedPubKey, err := types.ParsePubKey(server.node.Info().PublicKey)
	require.NoError(t, err)

	require.Equal(t, *expectedPubKey, *pubKey)
}

func TestDecryptWithKeyHandler(t *testing.T) {
	port := 8883
	proxyPort := 5505
	server := setupTestServer(t, proxyPort, port)
	go server.Serve()                        //nolint:errcheck
	defer server.Close(context.Background()) //nolint:errcheck

	wallet := setupTestWallet(t, server.wStorage, wallets.XRPAlgo)
	walletID, keyID := wallet.WalletID, wallet.KeyID

	// Create test encrypted message (this is a dummy encrypted message for testing)
	message := []byte("encrypted test message")

	encryptedMessage, err := encrypt(message, &wallets.ToECDSAUnsafe(wallet.PrivateKey).PublicKey)
	require.NoError(t, err)

	// Create request body
	requestBody := types.DecryptRequest{
		EncryptedMessage: encryptedMessage,
	}
	url := fmt.Sprintf("http://localhost:%d/decrypt/%s/%d", port, walletID.Hex(), keyID)
	body, err := post(url, requestBody)
	require.NoError(t, err)

	// Parse response
	var response types.DecryptResponse
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// Verify response structure
	require.Equal(t, message, response.DecryptedMessage)
}

func TestDecryptWithTeeHandler(t *testing.T) {
	port := 8884
	proxyPort := 5506
	server := setupTestServer(t, proxyPort, port)
	go server.Serve()                        //nolint:errcheck
	defer server.Close(context.Background()) //nolint:errcheck

	// Create test encrypted message (this is a dummy encrypted message for testing)
	message := []byte("encrypted test message")

	teePubKey, err := types.ParsePubKey(server.node.Info().PublicKey)
	require.NoError(t, err)
	encryptedMessage, err := encrypt(message, teePubKey)
	require.NoError(t, err)

	// Create request body
	requestBody := types.DecryptRequest{
		EncryptedMessage: encryptedMessage,
	}
	url := fmt.Sprintf("http://localhost:%d/decrypt", port)
	body, err := post(url, requestBody)
	require.NoError(t, err)

	// Parse response
	var response types.DecryptResponse
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// Verify response structure
	require.Equal(t, message, response.DecryptedMessage)
}

func TestPostResultHandler(t *testing.T) {
	port := 8885
	proxyPort := 5503
	server := setupTestServer(t, proxyPort, port)
	go server.Serve()                        //nolint:errcheck
	defer server.Close(context.Background()) //nolint:errcheck

	actionResponseChan := make(chan *types.ActionResponse, 1)
	go mockProxyResult(t, proxyPort, actionResponseChan)

	actionResult := types.ActionResult{
		ID:            common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
		SubmissionTag: types.Submit,
		Status:        1,
		Log:           "test log",
		Version:       "1.0.0",

		AdditionalResultStatus: hexutil.Bytes{},
		Data:                   hexutil.Bytes{},
	}

	url := fmt.Sprintf("http://localhost:%d/result", port)
	_, err := post(url, actionResult)
	require.NoError(t, err)

	actionResponse2 := <-actionResponseChan
	require.Equal(t, actionResult, actionResponse2.Result)
}

func mockProxyResult(t *testing.T, proxyPort int, actionResponseChan chan *types.ActionResponse) {
	router := http.NewServeMux()

	router.HandleFunc("POST /result", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var actionResponse types.ActionResponse
		err = json.Unmarshal(body, &actionResponse)
		require.NoError(t, err)

		actionResponseChan <- &actionResponse
		err = r.Body.Close()
		require.NoError(t, err)
	})

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", proxyPort), router))
}

func post(url string, req any) ([]byte, error) {
	requestBody, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	res, err := http.Post(url, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}

	defer res.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d, response: %s", res.StatusCode, string(body))
	}

	return body, nil
}
