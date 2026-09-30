package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/hash"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/settings"
	walletstorage "github.com/flare-foundation/tee-node/internal/wallets"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
	wallets "github.com/flare-foundation/tee-node/pkg/wallets"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/stretchr/testify/require"
)

// unusedProxyURL is for tests that never reach the proxy.
const unusedProxyURL = "http://127.0.0.1:0"

func setupTestServer(t *testing.T, proxyURL string, port int) *SignServer {
	t.Helper()

	testNode, err := node.Initialize(node.ZeroState{})
	require.NoError(t, err)
	require.NoError(t, testNode.SetChainID(31337))

	wStorage := walletstorage.InitializeStorage()

	return NewSignServer(port, testNode, wStorage, &settings.ProxyURLMutex{URL: proxyURL})
}

// startTestServer serves s on an ephemeral loopback port until the test ends and returns its base URL.
// Fixed ports collide across concurrently running test binaries.
func startTestServer(t *testing.T, s *SignServer) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	served := make(chan error, 1)
	go func() { served <- s.server.Serve(ln) }()

	t.Cleanup(func() {
		require.NoError(t, s.Close(context.Background()))
		require.ErrorIs(t, <-served, http.ErrServerClosed)
	})

	return "http://" + ln.Addr().String()
}

func TestSignServerBindsLoopback(t *testing.T) {
	// The sign/decrypt API is unauthenticated and must not listen on all
	// interfaces; it always binds to loopback.
	require.Equal(t, "127.0.0.1", settings.SignHost)

	server := setupTestServer(t, unusedProxyURL, 8899)
	require.Equal(t, "127.0.0.1:8899", server.server.Addr)
}

func setupTestWallet(t *testing.T, ws *walletstorage.Storage, signingAlgo common.Hash) *wallets.Wallet {
	t.Helper()

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

	ws.Lock()
	// Store wallet in storage
	err = ws.Store(wallet)
	require.NoError(t, err)
	ws.Unlock()

	ws.RLock()
	// Verify wallet was stored
	storedWallet, err := ws.Get(wallets.KeyIDPair{WalletID: walletID, KeyID: keyID})
	require.NoError(t, err)
	require.NotNil(t, storedWallet)
	defer ws.RUnlock()

	return wallet
}

func TestGetKeyInfo(t *testing.T) {
	extServer := setupTestServer(t, unusedProxyURL, 0)
	base := startTestServer(t, extServer)

	testWallet := setupTestWallet(t, extServer.wStorage, wallets.XRPSignAlgo)
	wID, kID := testWallet.WalletID, testWallet.KeyID
	url := fmt.Sprintf("%s/key-info/%s/%d", base, wID.Hex(), kID)

	resp, err := http.Get(url)
	require.NoError(t, err)

	defer resp.Body.Close() //nolint:errcheck

	// Assert response
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var response wallet.IWalletKeyManagerKeyExistence

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&response)
	require.NoError(t, err)

	// Check that the wallet ID and key ID match
	require.Equal(t, wID.Hex(), common.BytesToHash(response.WalletId[:]).Hex())
	require.Equal(t, kID, response.KeyId)
	require.Equal(t, kID, response.KeyId)
}

func TestSignWithKey(t *testing.T) {
	server := setupTestServer(t, unusedProxyURL, 0)
	base := startTestServer(t, server)

	wallet := setupTestWallet(t, server.wStorage, wallets.XRPSignAlgo)
	wID, kID := wallet.WalletID, wallet.KeyID

	// Create test message
	message := crypto.Keccak256([]byte("test message to sign"))

	// Create request body
	requestBody := types.SignRequest{
		Message: message,
	}

	url := fmt.Sprintf("%s/sign/%s/%d", base, wID.Hex(), kID)
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

func TestSignWithTee(t *testing.T) {
	server := setupTestServer(t, unusedProxyURL, 0)
	base := startTestServer(t, server)

	// Create test message
	message := []byte("test message to sign with TEE")

	// Create request body
	requestBody := types.SignRequest{
		Message: message,
	}

	// Create request
	url := base + "/sign"
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

func TestDecryptWithKey(t *testing.T) {
	server := setupTestServer(t, unusedProxyURL, 0)
	base := startTestServer(t, server)

	wallet := setupTestWallet(t, server.wStorage, wallets.XRPSignAlgo)
	walletID, keyID := wallet.WalletID, wallet.KeyID

	// Create test encrypted message (this is a dummy encrypted message for testing)
	message := []byte("encrypted test message")

	encryptedMessage, err := utils.Encrypt(message, &wallets.ToECDSAUnsafe(wallet.PrivateKey).PublicKey)
	require.NoError(t, err)

	// Create request body
	requestBody := types.DecryptRequest{
		EncryptedMessage: encryptedMessage,
	}
	url := fmt.Sprintf("%s/decrypt/%s/%d", base, walletID.Hex(), keyID)
	body, err := post(url, requestBody)
	require.NoError(t, err)

	// Parse response
	var response types.DecryptResponse
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// Verify response structure
	require.Equal(t, message, response.DecryptedMessage)
}

func TestDecryptWithTee(t *testing.T) {
	server := setupTestServer(t, unusedProxyURL, 0)
	base := startTestServer(t, server)

	// Create test encrypted message (this is a dummy encrypted message for testing)
	message := []byte("encrypted test message")

	teePubKey, err := types.ParsePubKey(server.node.Info().PublicKey)
	require.NoError(t, err)
	encryptedMessage, err := utils.Encrypt(message, teePubKey)
	require.NoError(t, err)

	// Create request body
	requestBody := types.DecryptRequest{
		EncryptedMessage: encryptedMessage,
	}
	url := base + "/decrypt"
	body, err := post(url, requestBody)
	require.NoError(t, err)

	// Parse response
	var response types.DecryptResponse
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// Verify response structure
	require.Equal(t, message, response.DecryptedMessage)
}

func TestPostResult(t *testing.T) {
	actionResponseChan := make(chan *types.ActionResponse, 1)
	proxy := mockProxyResult(t, actionResponseChan)
	server := setupTestServer(t, proxy.URL, 0)
	base := startTestServer(t, server)

	actionResult := types.ActionResult{
		ID:            common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
		SubmissionTag: types.Submit,
		Status:        1,
		Log:           "test log",
		Version:       "1.0.0",

		AdditionalResultStatus: hexutil.Bytes{},
		Data:                   hexutil.Bytes{},
	}

	url := base + "/result"
	_, err := post(url, actionResult)
	require.NoError(t, err)

	actionResponse2 := <-actionResponseChan
	require.Equal(t, actionResult, actionResponse2.Result)
}

func mockProxyResult(t *testing.T, actionResponseChan chan *types.ActionResponse) *httptest.Server {
	t.Helper()

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

	proxy := httptest.NewServer(router)
	t.Cleanup(proxy.Close)

	return proxy
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
