package service

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"tee-node/pkg/service/instructionservice"
	"tee-node/pkg/service/nodeservice"
	"tee-node/pkg/service/policyservice"
	walletsservice "tee-node/pkg/service/walletservice"

	"github.com/flare-foundation/go-flare-common/pkg/logger"

	"github.com/gorilla/mux"
)

func HandlerGenerator[T any, R any](f func(req *T) (*R, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req T
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
	router.HandleFunc("/wallet", HandlerGenerator(walletsservice.WalletInfo)).Methods("POST")
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
