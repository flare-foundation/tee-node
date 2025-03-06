package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"

	api "tee-node/api/types"

	attestationserver "tee-node/internal/attestation"
	policyserver "tee-node/internal/policy"
	utilsserver "tee-node/internal/utils"
	utils "tee-node/tests"
	"tee-node/tests/client/config"
	"tee-node/tests/client/policy"
	"tee-node/tests/client/xrpl"

	"github.com/ethereum/go-ethereum/rpc"

	"github.com/alexflint/go-arg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/database"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
)

var args struct {
	Call          string
	Arg1          string
	Provider      int
	WalletName    string
	PubKey        string
	TeeId         string
	InstructionId string
	TeeIds        []string
	Address       string
	RewardEpochId uint32
	Config        string `default:"tests/configs/config_client.toml"`
}

// TODO: make cli configurable calls
func main() {
	arg.MustParse(&args)

	config, err := config.ReadConfig(args.Config)
	if err != nil {
		log.Fatalf("failed to read config: %v", err)
	}

	client, err := rpc.Dial(config.Server.Host)
	if err != nil {
		log.Fatalf("Failed to connect to RPC server: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	nonceBytes, err := utilsserver.GenerateRandomBytes(32)
	if err != nil {
		log.Fatalf("%v", err)
	}

	switch args.Call {
	case "generate_voters":
		var numVoters int
		if args.Arg1 == "" {
			numVoters = 3
		} else {
			numVoters, err = strconv.Atoi(args.Arg1)
			if err != nil {
				log.Fatalf("%v", err)
			}
		}
		voters, privKeys := utils.GenerateRandomVoters(numVoters)

		providers := &utils.Providers{Voters: voters, PrivKeys: privKeys}

		// Marshal Providers
		jsonStr, err := utils.MarshalProviders(providers)
		if err != nil {
			log.Fatalf("%v", err)
		}
		f, err := os.Create("tests/test_providers.json")
		if err != nil {
			log.Fatalf("%v", err)
		}
		_, err = f.Write(jsonStr)
		if err != nil {
			log.Fatalf("%v", err)
		}

	case "initial_policy":
		db, err := database.Connect(&config.DB)
		if err != nil {
			log.Fatalf("failed to connect to DB: %v", err)
		}
		params := policy.PolicyHistoryParams{RelayContractAddress: common.HexToAddress(config.Chain.RelayContractAddress), FlareSystemManagerContractAddress: common.HexToAddress(config.Chain.FlareSystemManagerContractAddress)}

		policies, signatures, err := policy.FetchPolicyHistory(ctx, &params, db)
		if err != nil {
			log.Fatalf("could not fetch policy: %v", err)
		}
		req, err := policy.CreateSigningRequest(policies, signatures)
		if err != nil {
			log.Fatalf("could not create signing request: %v", err)
		}

		var resp api.InitializePolicyResponse
		err = client.Call(&resp, "policyservice_initializePolicy", req)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}
		logger.Info("fetched and initialized policies")

	case "initial_policy_simulate":
		providersBytes, err := os.ReadFile("tests/test_providers.json")
		if err != nil {
			log.Fatalf("%v", err)
		}
		providers, err := utils.UnmarshalProviders(providersBytes)
		if err != nil {
			log.Fatalf("%v", err)
		}

		epochId, randSeed := uint32(1), int64(12345)
		initialPolicy := utils.GenerateRandomPolicyData(epochId, providers.Voters, randSeed)
		initialPolicyBytes, err := policyserver.EncodeSigningPolicy(&initialPolicy)
		if err != nil {
			log.Fatalf("%v", err)
		}

		hash := policyserver.SigningPolicyHash(initialPolicyBytes)
		fmt.Println(hex.EncodeToString(hash))

		numPolicies := 5
		policySignaturesArray, err := utils.GenerateRandomMultiSignedPolicyArray(epochId, randSeed, providers.Voters, providers.PrivKeys, numPolicies)
		if err != nil {
			log.Fatalf("could not generate random policy policy: %v", err)
		}

		req := &api.InitializePolicyRequest{
			InitialPolicyBytes: initialPolicyBytes,
			NewPolicyRequests:  policySignaturesArray,
		}

		var resp api.InitializePolicyResponse
		err = client.Call(&resp, "policyservice_initializePolicy", req)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}
		logger.Info("initialized policies")

	case "new_wallet":
		providerPrivKey, err := getProviderPrivKey(args.Provider)
		if err != nil {
			log.Fatalf("could not get provider private key: %v", err)
		}

		instruction, err := utils.BuildMockInstruction("WALLET",
			"KEY_GENERATE",
			api.NewWalletRequest{
				Name: args.WalletName},
			providerPrivKey,
			args.TeeId,
			args.InstructionId,
			args.RewardEpochId,
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		var resp api.InstructionResponse
		err = client.Call(&resp, "instructionservice_sendSignedInstruction", instruction)
		if err != nil {
			log.Fatalf("could not create a new wallet: %v", err)
		}

		logger.Infof("created a wallet: finalized:%v", resp.Finalized)

	case "pub_key":
		// TODO: Remove this function

		req := &api.WalletInfoRequest{
			Name:      args.WalletName,
			Challenge: hex.EncodeToString(nonceBytes),
		}

		var pubKeyResp api.WalletInfoResponse
		err = client.Call(&pubKeyResp, "instructionservice_walletInfo", req)
		if err != nil {
			log.Fatalf("could not get a public key: %v", err)
		}
		logger.Infof("ethAddress: %s, public key: %s, attestation token %s", pubKeyResp.EthAddress, pubKeyResp.EthPublicKey.X, pubKeyResp.Token)

	case "wallet_info":
		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalf("%v", err)
		}

		req := &api.WalletInfoRequest{
			Name:      args.WalletName,
			Challenge: hex.EncodeToString(nonceBytes),
		}

		var accInfoResp api.WalletInfoResponse
		err = client.Call(&accInfoResp, "instructionservice_walletInfo", req)
		if err != nil {
			log.Fatalf("could not get wallet info: %v", err)
		}
		logger.Infof("EthAddress: %s, XrpAddress: %s, PublicKey: %s, Attestation Token %s", accInfoResp.EthAddress, accInfoResp.XrpAddress, accInfoResp.XrpPublicKey, accInfoResp.Token)

	case "node_attestation":
		var resp api.GetNodeInfoResponse
		err = client.Call(&resp, "nodeservice_getNodeInfo", &api.GetNodeInfoRequest{Nonce: string(nonceBytes)})
		if err != nil {
			log.Fatalf("could not get attestation: %v", err)
		}

		teeId := resp.Data.Id
		pubKey := resp.Data.EncryptionPublicKey

		logger.Infof("TeeId: %v PubKey: %v\n", teeId, pubKey)
		logger.Infof("node info: %v", resp.Data)

		if resp.Token != "magic_pass" {
			cert, err := attestationserver.LoadRootCert("google_confidential_space_root.crt")
			if err != nil {
				log.Fatalf("could not load certificate: %v", err)
			}
			token, err := attestationserver.ValidatePKIToken(cert, resp.Token)
			if err != nil {
				log.Fatalf("failed validating PKI token: %v", err)
			}

			hash, err := resp.Data.Hash()
			if err != nil {
				log.Fatalf("failed validating PKI token: %v", err)
			}
			ok, err := attestationserver.ValidateClaims(token, []string{string(nonceBytes), "GetNodeInfo", hash})
			if err != nil || !ok {
				log.Fatalf("failed validating PKI token: %v", err)
			}
		} else {
			logger.Infof("no token")
		}

	case "hash_payment":
		// ---------- Parse arguments ---------- //

		type PaymentFields struct {
			Amount             uint64 `json:"amount"`
			Fee                uint64 `json:"fee"`
			SpenderAccount     string `json:"spenderAccount"`
			DestinationAccount string `json:"destinationAccount"`
			Sequence           uint32 `json:"sequence"`
			LastLedgerSeq      uint32 `json:"lastLedgerSeq"`
			SignerAddress      string `json:"signerAddress"`
		}

		// Unmarshal JSON
		var paymentFields PaymentFields
		err = json.Unmarshal([]byte(args.Arg1), &paymentFields)
		if err != nil {
			log.Fatalf("Failed to parse JSON: %v", err)
		}

		// ---------- Encode and Hash the transaction ---------- //

		payment, err := xrpl.ConstructPaymentTransaction(paymentFields.Amount, paymentFields.Fee, paymentFields.SpenderAccount, paymentFields.DestinationAccount, paymentFields.Sequence, paymentFields.LastLedgerSeq)
		if err != nil {
			log.Fatalf("could not construct payment transaction: %v", err)
		}

		encodedTx, _ := xrpl.EncodeTransaction(payment, paymentFields.SignerAddress)
		if err != nil {
			log.Fatalf("could not construct payment transaction: %v", err)
		}

		txHash := xrpl.HashXRPMessage(encodedTx)

		logger.Infof("Payment hash: %v", hex.EncodeToString(txHash))

	case "sign_payment":
		// ---------- Parse arguments ---------- //
		providerPrivKey, err := getProviderPrivKey(args.Provider)
		if err != nil {
			log.Fatalf("could not get provider private key: %v", err)
		}

		paymentHash := args.Arg1

		txHash, err := hex.DecodeString(paymentHash)
		if err != nil {
			log.Fatalf("could not decode tx hash: %v", err)
		}

		// ---------- Sign the message request ---------- //

		instruction, err := utils.BuildMockInstruction(
			"XRP",
			"PAY",
			api.SignPaymentRequest{WalletName: args.WalletName, PaymentHash: paymentHash},
			providerPrivKey,
			args.TeeId,
			args.InstructionId,
			args.RewardEpochId,
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		// ---------- Send the transaction to the signing service ---------- //

		var resp api.InstructionResponse
		err = client.Call(&resp, "instructionservice_sendSignedInstruction", instruction)
		if err != nil {
			log.Fatalf("could not sign payment transaction: %v", err)
		}

		logger.Info("Payment hash: %v", hex.EncodeToString(txHash))
		logger.Infof("sent request to SignPaymentTransaction, is ThresholdReached %v, Data %s, Token %v", resp.Finalized, resp.Data, resp.Token)

	case "get_payment_signature":
		nonceBytes, _ := utilsserver.GenerateRandomBytes(32)

		req := &api.InstructionResultRequest{
			InstructionId: args.InstructionId,
			Challenge:     hex.EncodeToString(nonceBytes),
		}

		var resp api.InstructionResultResponse
		err = client.Call(&resp, "instructionservice_instructionResult", req)
		if err != nil {
			log.Fatalf("could not get the payment signature : %v", err)
		}

		var paymentSigResponse api.GetPaymentSignatureResponse
		err := json.Unmarshal(resp.Data, &paymentSigResponse)
		if err != nil {
			log.Fatalf("could not decode the payment signature : %v", err)
		}

		txnSignature := hex.EncodeToString(paymentSigResponse.TxnSignature)
		signingPubKey := hex.EncodeToString(paymentSigResponse.SigningPubKey)

		logger.Infof("sent request to GetPaymentSignature, is Account %v, TxnSignature %s, PublicKey %s, Token %v",
			paymentSigResponse.Account, txnSignature, signingPubKey, resp.Token)

	case "split_wallet":
		providerPrivKey, err := getProviderPrivKey(args.Provider)
		if err != nil {
			log.Fatalf("could not get provider private key: %v", err)
		}

		type NodeInfo struct {
			TeeId  string `json:"tee_id"`
			PubKey string `json:"pub_key"`
		}

		// Parse the JSON
		var nodeInfos []NodeInfo
		if err := json.Unmarshal([]byte(args.Arg1), &nodeInfos); err != nil {
			log.Fatalf("Failed to parse JSON: %v", err)
		}

		teeIds := make([]string, len(nodeInfos))
		pubKeys := make([]string, len(nodeInfos))
		for i, info := range nodeInfos {
			teeIds[i] = info.TeeId
			pubKeys[i] = info.PubKey
		}

		// ---------- Split the wallet request ---------- //
		instruction, err := utils.BuildMockInstruction("WALLET",
			"KEY_MACHINE_BACKUP",
			api.SplitWalletRequest{
				Name:       args.WalletName,
				TeeIds:     teeIds,
				Hosts:      config.Server.Backups,
				PublicKeys: pubKeys,
				Threshold:  int64(config.Server.BackupsThreshold),
			},
			providerPrivKey,
			args.TeeId,
			args.InstructionId,
			args.RewardEpochId,
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		var resp api.InstructionResponse
		err = client.Call(&resp, "instructionservice_sendSignedInstruction", instruction)
		if err != nil {
			log.Fatalf("could not split wallet: %v", err)
		}

		logger.Infof("sent request to split wallet, is finalized %v", resp.Finalized)

	case "recover_wallet":
		providerPrivKey, err := getProviderPrivKey(args.Provider)
		if err != nil {
			log.Fatalf("could not get provider private key: %v", err)
		}

		numBackups := len(config.Server.Backups)

		shareIds := make([]string, numBackups)
		for i := range shareIds {
			shareIds[i] = strconv.Itoa(i + 1)
		}
		request := api.RecoverWalletRequest{
			Name:      args.WalletName,
			TeeIds:    args.TeeIds,
			Hosts:     config.Server.Backups,
			ShareIds:  shareIds,
			PublicKey: args.PubKey,
			Address:   args.Address,
			Threshold: int64(config.Server.BackupsThreshold),
		}

		instruction, err := utils.BuildMockInstruction("WALLET", "KEY_MACHINE_RESTORE", request, providerPrivKey,
			args.TeeId,
			args.InstructionId,
			args.RewardEpochId,
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		var resp api.InstructionResponse
		err = client.Call(&resp, "instructionservice_sendSignedInstruction", instruction)
		if err != nil {
			log.Fatalf("could not recover: %v", err)
		}

		logger.Infof("sent request to recover wallet, is finalized %v, attestation token %s", resp.Finalized, resp.Token)

	default:
		logger.Warn("call not recognized")
	}
}

func getProviderPrivKey(providerNum int) (*ecdsa.PrivateKey, error) {
	providersBytes, err := os.ReadFile("tests/test_providers.json")
	if err != nil {
		log.Fatalf("%v", err)
	}
	providers, err := utils.UnmarshalProviders(providersBytes)
	if err != nil {
		log.Fatalf("%v", err)
	}
	providerPrivKey := providers.PrivKeys[providerNum]

	return providerPrivKey, nil
}
