package service

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"tee-node/api/types"
	"tee-node/pkg/service/instructionservice"
	"tee-node/pkg/service/nodeservice"
	"tee-node/pkg/service/policyservice"
	walletsservice "tee-node/pkg/service/walletservice"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"

	"github.com/gorilla/mux"
)

type ValidRequestType interface {
	instruction.Instruction | types.InstructionResultRequest | types.InitializePolicyRequest |
		types.GetActivePolicyRequest | types.WalletInfoRequest | types.WalletGetBackupRequest |
		types.WalletUploadBackupRequest | types.WalletGetBackupShareRequest | types.WalletUploadBackupShareRequest | types.GetNodeInfoRequest
}

func HandlerGenerator[T ValidRequestType, R any](f func(req *T) (*R, error)) http.HandlerFunc {
	var maxBodySize int64
	switch any(new(T)).(type) {
	case *instruction.Instruction:
		maxBodySize = 100 * 1024 // 100 KB
	case *types.InstructionResultRequest:
		maxBodySize = 1024 // 1 KB
	case *types.InitializePolicyRequest:
		maxBodySize = 200 * 1024 // 200 KB
	case *types.GetActivePolicyRequest:
		maxBodySize = 1024 // 1 KB
	case *types.WalletInfoRequest:
		maxBodySize = 1024 // 1 KB
	case *types.WalletGetBackupRequest:
		maxBodySize = 1024 // 1 KB
	case *types.WalletUploadBackupRequest:
		maxBodySize = 1024 * 1024 // 1 MB
	case *types.WalletGetBackupShareRequest:
		maxBodySize = 1024 // 1 KB
	case *types.WalletUploadBackupShareRequest:
		maxBodySize = 200 * 1024 // 200 KB
	case *types.GetNodeInfoRequest:
		maxBodySize = 1024 // 1 KB
	default:
		return func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Invalid request type", http.StatusBadRequest)
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var req T
		// Check if the request body size exceeds the limit
		if r.ContentLength > maxBodySize {
			http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
			return
		}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		res, err := f(&req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(res)
		if err != nil {
			http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)
			return
		}
	}
}

func RegisterInstructionsRoutes(router *mux.Router) {
	instructionsRouter := router.PathPrefix("/instruction").Subrouter()

	instructionsRouter.HandleFunc("", HandlerGenerator(instructionservice.SendSignedInstruction)).Methods("POST")
	instructionsRouter.HandleFunc("/result", HandlerGenerator(instructionservice.InstructionResult)).Methods("POST")
	instructionsRouter.HandleFunc("/status", HandlerGenerator(instructionservice.InstructionStatus)).Methods("POST")
}

func RegisterPolicyRoutes(router *mux.Router) {
	policiesRouter := router.PathPrefix("/policies").Subrouter()

	policiesRouter.HandleFunc("/initialize", HandlerGenerator(policyservice.InitializePolicy)).Methods("POST")
	policiesRouter.HandleFunc("/latest", HandlerGenerator(policyservice.GetActivePolicy)).Methods("POST")
}

func RegisterWalletRoutes(router *mux.Router) {
	walletRouter := router.PathPrefix("/wallet").Subrouter()

	walletRouter.HandleFunc("", HandlerGenerator(walletsservice.WalletInfo)).Methods("POST")
	walletRouter.HandleFunc("/get-backup", HandlerGenerator(walletsservice.WalletGetBackupPackage)).Methods("POST")
	walletRouter.HandleFunc("/upload-backup-package", HandlerGenerator(walletsservice.WalletUploadBackupPackage)).Methods("POST")
	walletRouter.HandleFunc("/get-backup-shares", HandlerGenerator(walletsservice.WalletGetBackupShare)).Methods("POST")
	walletRouter.HandleFunc("/upload-backup-shares", HandlerGenerator(walletsservice.WalletUploadBackupShare)).Methods("POST")
}

func RegisterNodeRoutes(router *mux.Router) {
	router.HandleFunc("/info", HandlerGenerator(nodeservice.GetNodeInfo)).Methods("POST")
}

func LaunchServer(port int) {
	router := mux.NewRouter()

	RegisterInstructionsRoutes(router)
	RegisterWalletRoutes(router)
	RegisterPolicyRoutes(router)
	RegisterNodeRoutes(router)

	logger.Info("HTTP Server running on ", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), router))
}
