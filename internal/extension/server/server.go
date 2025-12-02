package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/flare-foundation/tee-node/internal/router"
	"github.com/flare-foundation/tee-node/internal/router/queue"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/flare-foundation/tee-node/pkg/wallets"
)

const (
	actionID      = "actionID"
	instructionID = "instructionID"
	keyID         = "keyID"
	rewardEpochID = "rewardEpochID"
	walletID      = "walletID"
)

type ExtenderServer struct {
	server *http.Server

	wStorage *wallets.Storage

	node *node.Node

	proxyURL *settings.ProxyURLMutex
}

// NewExtenderServer constructs an HTTP server that exposes wallet and TEE
// functionality to extension clients on the provided port.
func NewExtenderServer(port int, node *node.Node, wStorage *wallets.Storage, proxyURL *settings.ProxyURLMutex) *ExtenderServer {
	addr := fmt.Sprintf(":%d", port)

	server := &http.Server{
		Addr: addr, // todo
		// ReadTimeout:                  0,
		// ReadHeaderTimeout:            0,
		// WriteTimeout:                 0,
		// IdleTimeout:                  0,
		// MaxHeaderBytes:               0,
	}

	e := ExtenderServer{
		server:   server,
		wStorage: wStorage,
		node:     node,
		proxyURL: proxyURL,
	}

	e.registerRoutes()

	return &e
}

// Serve starts the server.
func (s *ExtenderServer) Serve() error {
	return s.server.ListenAndServe()
}

// Close gracefully closes the server.
func (s *ExtenderServer) Close(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func (s *ExtenderServer) registerRoutes() {
	mux := http.NewServeMux()
	s.server.Handler = addContentType(mux, "application/json")

	mux.HandleFunc(fmt.Sprintf("GET /key-info/{%s}/{%s}", walletID, keyID), s.getKeyInfoHandler)
	mux.HandleFunc(fmt.Sprintf("POST /sign/{%s}/{%s}", walletID, keyID), s.signWithKeyHandler)
	mux.HandleFunc("POST /sign", s.signWithTeeHandler)

	mux.HandleFunc("POST /result", s.postResultHandler)
	mux.HandleFunc(fmt.Sprintf("POST /decrypt/{%s}/{%s}", walletID, keyID), s.decryptWithKeyHandler)
	mux.HandleFunc("POST /decrypt", s.decryptWithTeeHandler)
}

// getKeyInfoHandler handles GET /key-info/{walletID}/{keyID}.
func (s *ExtenderServer) getKeyInfoHandler(w http.ResponseWriter, r *http.Request) {
	wID, err := hashParam(r, walletID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	kID, err := uint64Param(r, keyID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	wallet, err := s.wStorage.Get(wallets.KeyIDPair{WalletID: wID, KeyID: kID})
	if err != nil {
		if errors.Is(err, wallets.ErrWalletNonExistent) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	walletInfo := wallet.KeyExistenceProof(s.node.TeeID())

	response, err := json.Marshal(walletInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = w.Write(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// signWithKeyHandler handles POST /sign/{walletID}/{keyID}.
func (s *ExtenderServer) signWithKeyHandler(w http.ResponseWriter, r *http.Request) {
	wID, err := hashParam(r, walletID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	kID, err := uint64Param(r, keyID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Parse request body
	var signRequest types.SignRequest

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&signRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	wallet, err := s.wStorage.Get(wallets.KeyIDPair{WalletID: wID, KeyID: kID})
	if err != nil {
		if errors.Is(err, wallets.ErrWalletNonExistent) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Sign the message with the wallet's private key
	signature, err := wallet.Sign(signRequest.Message)
	if err != nil {
		http.Error(w, "can not sign", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(types.SignResponse{
		Message:   signRequest.Message,
		Signature: signature,
	})

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// signWithTeeHandler handles POST /sign.
func (s *ExtenderServer) signWithTeeHandler(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var signRequest types.SignRequest

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&signRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(signRequest.Message) == 0 {
		http.Error(w, "message is required", http.StatusBadRequest)
		return
	}

	// Sign the message with the TEE's private key
	msgHash := crypto.Keccak256(signRequest.Message)
	signature, err := s.node.Sign(msgHash)
	if err != nil {
		http.Error(w, "can not sign", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(types.SignResponse{
		Message:   signRequest.Message,
		Signature: signature,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// postResultHandler handles POST /result.
func (s *ExtenderServer) postResultHandler(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var result types.ActionResult

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&result); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response, err := router.SignResult(&result, s.node)
	if err != nil {
		http.Error(w, "can not sign", http.StatusInternalServerError)
	}

	s.proxyURL.RLock()
	url := s.proxyURL.URL
	s.proxyURL.RUnlock()

	if url == "" {
		http.Error(w, "proxy not set", http.StatusInternalServerError)
		return
	}

	var postErr error
	deadline := time.Now().Add(100 * time.Millisecond)
	for {
		postErr = queue.PostActionResponse(fmt.Sprintf("%s/result", url), response)
		if postErr == nil {
			break
		}
		if time.Now().After(deadline) {
			http.Error(w, postErr.Error(), http.StatusInternalServerError)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Return success response with empty body
	w.WriteHeader(http.StatusOK)
}

// decryptWithKeyHandler handles POST /decrypt/{walletD}/{keyID}.
func (s *ExtenderServer) decryptWithKeyHandler(w http.ResponseWriter, r *http.Request) {
	wID, err := hashParam(r, walletID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	kID, err := uint64Param(r, keyID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Parse request body
	var decryptRequest types.DecryptRequest

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decryptRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(decryptRequest.EncryptedMessage) == 0 {
		http.Error(w, "message is required", http.StatusBadRequest)
		return
	}

	wallet, err := s.wStorage.Get(wallets.KeyIDPair{WalletID: wID, KeyID: kID})
	if err != nil {
		if errors.Is(err, wallets.ErrWalletNonExistent) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	decryptedMessage, err := wallet.Decrypt(decryptRequest.EncryptedMessage)
	if err != nil {
		http.Error(w, "can not decrypt", http.StatusBadRequest)
	}

	// Return success response
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(types.DecryptResponse{
		DecryptedMessage: decryptedMessage,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// decryptWithTeeHandler handles POST /decrypt.
func (s *ExtenderServer) decryptWithTeeHandler(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var decryptRequest types.DecryptRequest

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decryptRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(decryptRequest.EncryptedMessage) == 0 {
		http.Error(w, "message is required", http.StatusBadRequest)
		return
	}

	// Decrypt the message with the TEE's private key
	decryptedMessage, err := s.node.Decrypt(decryptRequest.EncryptedMessage)
	if err != nil {
		http.Error(w, "can not decrypt", http.StatusBadRequest)
	}
	// Return success response
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(types.DecryptResponse{
		DecryptedMessage: decryptedMessage,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// encrypt wraps the ECIES encryption helper for plaintext using the provided
// public key.
func encrypt(plaintext []byte, publicKey *ecdsa.PublicKey) ([]byte, error) {
	pk, err := utils.ECDSAPubKeyToECIES(publicKey)
	if err != nil {
		return nil, err
	}

	privKeyEncryption, err := ecies.Encrypt(rand.Reader, pk, plaintext, nil, nil)
	if err != nil {
		return nil, err
	}

	return privKeyEncryption, nil
}

func uint64Param(r *http.Request, param string) (uint64, error) {
	s := r.PathValue(param)
	s64, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, invalidParam(param)
	}

	return s64, err
}

func hashParam(r *http.Request, param string) (common.Hash, error) {
	s := r.PathValue(param)

	s = strings.ToLower(s)
	s, _ = strings.CutPrefix(s, "0x")

	sB, err := hex.DecodeString(s)
	if err != nil {
		return common.Hash{}, invalidParam(param)
	}
	if len(sB) != 32 {
		return common.Hash{}, invalidParam(param)
	}

	return common.BytesToHash(sB), nil
}

func invalidParam(param string) error {
	return fmt.Errorf("invalid %s", param)
}

func addContentType(h http.Handler, contentType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", contentType)
		h.ServeHTTP(w, r)
	})
}
