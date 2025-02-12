package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"

	api "tee-node/api/types"

	policyserver "tee-node/internal/policy"
	"tee-node/internal/requests"
	utilsserver "tee-node/internal/utils"
	"tee-node/internal/wallets"
	utils "tee-node/tests"
	"tee-node/tests/client/attestation"
	"tee-node/tests/client/config"
	"tee-node/tests/client/policy"

	"github.com/ethereum/go-ethereum/rpc"

	"github.com/alexflint/go-arg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/database"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
)

const GCP_INSTANCE_IP = "localhost"

var args struct {
	Call   string
	Arg1   string
	Arg2   string
	Arg3   string
	Config string `default:"tests/configs/config_client.toml"`
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
		policySignaturesArray, err := utils.GenerateRandomSignNewPolicyRequestArrays(epochId, randSeed, providers.Voters, providers.PrivKeys, numPolicies)
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
		var providerNum int
		if args.Arg1 == "" {
			providerNum = 0
		} else {
			providerNum, err = strconv.Atoi(args.Arg1)
			if err != nil {
				log.Fatalf("%v", err)
			}
		}
		providersBytes, err := os.ReadFile("tests/test_providers.json")
		if err != nil {
			log.Fatalf("%v", err)
		}
		providers, err := utils.UnmarshalProviders(providersBytes)
		if err != nil {
			log.Fatalf("%v", err)
		}
		providerPrivKey := providers.PrivKeys[providerNum]

		walletName := args.Arg2
		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalf("%v", err)
		}

		newWalletRequest := wallets.NewNewWalletRequest(walletName)
		signature, err := requests.Sign(newWalletRequest, providerPrivKey)
		if err != nil {
			log.Fatalf("%v", err)
		}

		req := &api.NewWalletRequest{
			Name:      walletName,
			Nonce:     hex.EncodeToString(nonceBytes),
			Signature: signature,
		}
		var resp api.NewWalletResponse
		err = client.Call(&resp, "walletsservice_newWallet", req)
		if err != nil {
			log.Fatalf("could not create a new wallet: %v", err)
		}

		logger.Infof("created a wallet, attestation token %s", resp.Token)

	case "pub_key":
		walletName := args.Arg1
		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalf("%v", err)
		}

		req := &api.PublicKeyRequest{
			Name:  walletName,
			Nonce: hex.EncodeToString(nonceBytes),
		}

		var pubKeyResp api.PublicKeyResponse
		err = client.Call(&pubKeyResp, "walletsservice_publicKey", req)
		if err != nil {
			log.Fatalf("could not create a new wallet: %v", err)
		}
		logger.Infof("public key: %s, attestation token %s", pubKeyResp.Address, pubKeyResp.Token)

	case "google_attestation":
		var resp api.GetAttestationTokenResponse
		err = client.Call(&resp, "attestationservice_getAttestationToken", &api.GetAttestationTokenRequest{Nonces: []string{args.Arg1}})
		if err != nil {
			log.Fatalf("could not sign: %v", err)
		}

		jwtBytes := []byte(resp.JwtBytes)
		tokenClaims, err := attestation.VerifyAttestationToken(jwtBytes)
		if err != nil {
			log.Fatalf("could not verify the attestation token: %v", err)
		}

		jwtData, err := attestation.DecodeAttestationToken(tokenClaims)
		if err != nil {
			log.Fatalf("could not decode the token: %v", err)
		}

		log.Printf("Image Digest: %v\n", jwtData.Submods.Container.ImageDigest)
		log.Printf("Dbgstat: %v\n", jwtData.Dbgstat)
		log.Printf("Support Attributes: %v\n", jwtData.Submods.ConfidentialSpace.SupportAttributes)
		log.Printf("Hwmodel: %v\n", jwtData.Hwmodel)

	case "split_wallet":
		var providerNum int
		if args.Arg1 == "" {
			providerNum = 0
		} else {
			providerNum, err = strconv.Atoi(args.Arg1)
			if err != nil {
				log.Fatalf("%v", err)
			}
		}
		providersBytes, err := os.ReadFile("tests/test_providers.json")
		if err != nil {
			log.Fatalf("%v", err)
		}
		providers, err := utils.UnmarshalProviders(providersBytes)
		if err != nil {
			log.Fatalf("%v", err)
		}
		providerPrivKey := providers.PrivKeys[providerNum]

		walletName := args.Arg2
		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalf("%v", err)
		}

		numBackups := len(config.Server.Backups)
		newSplitWalletRequest, err := wallets.NewSplitWalletRequest(walletName, make([]string, numBackups), config.Server.Backups, config.Server.BackupsThreshold)
		if err != nil {
			log.Fatalf("%v", err)
		}
		signature, err := requests.Sign(newSplitWalletRequest, providerPrivKey)
		if err != nil {
			log.Fatalf("%v", err)
		}

		req := &api.SplitWalletRequest{
			Name:      walletName,
			TeeIds:    newSplitWalletRequest.IDs,
			Hosts:     newSplitWalletRequest.Hosts,
			Threshold: int64(newSplitWalletRequest.Threshold),
			Signature: signature,
			Nonce:     hex.EncodeToString(nonceBytes),
		}
		var resp api.SplitWalletResponse
		err = client.Call(&resp, "walletsservice_splitWallet", req)
		if err != nil {
			log.Fatalf("could not create a new wallet: %v", err)
		}

		logger.Infof("sent request to split wallet, is finalized %v, attestation token %s", resp.Finalized, resp.Token)

	case "recover_wallet":
		var providerNum int
		if args.Arg1 == "" {
			providerNum = 0
		} else {
			providerNum, err = strconv.Atoi(args.Arg1)
			if err != nil {
				log.Fatalf("%v", err)
			}
		}
		providersBytes, err := os.ReadFile("tests/test_providers.json")
		if err != nil {
			log.Fatalf("%v", err)
		}
		providers, err := utils.UnmarshalProviders(providersBytes)
		if err != nil {
			log.Fatalf("%v", err)
		}
		providerPrivKey := providers.PrivKeys[providerNum]

		walletName := args.Arg2
		address := args.Arg3

		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalf("%v", err)
		}

		numBackups := len(config.Server.Backups)

		shareIds := make([]string, numBackups)
		for i := range shareIds {
			shareIds[i] = strconv.Itoa(i + 1)
		}

		newRecoverWalletRequest, err := wallets.NewRecoverWalletRequest(walletName, make([]string, numBackups), config.Server.Backups, shareIds)
		if err != nil {
			log.Fatalf("%v", err)
		}
		signature, err := requests.Sign(newRecoverWalletRequest, providerPrivKey)
		if err != nil {
			log.Fatalf("%v", err)
		}

		req := &api.RecoverWalletRequest{
			Name:      walletName,
			TeeIds:    newRecoverWalletRequest.IDs,
			Hosts:     newRecoverWalletRequest.Hosts,
			ShareIds:  shareIds,
			Address:   address,
			Threshold: int64(config.Server.BackupsThreshold),
			Signature: signature,
			Nonce:     hex.EncodeToString(nonceBytes),
		}
		var resp api.RecoverWalletResponse
		err = client.Call(&resp, "walletsservice_recoverWallet", req)
		if err != nil {
			log.Fatalf("could not create a new wallet: %v", err)
		}

		logger.Infof("sent request to recover wallet, is finalized %v, attestation token %s", resp.Finalized, resp.Token)

	case "hardware_attestation":
		nonce := args.Arg1

		req := &api.GetHardwareAttestationRequest{
			Nonce: nonce,
		}
		var hardwareResp api.GetHardwareAttestationResponse
		err = client.Call(&hardwareResp, "attestationservice_getHardwareAttestation", req)
		if err != nil {
			log.Fatalf("could not sign: %v", err)
		}

		log.Printf("Hardware Attestation response: %v", hardwareResp.JsonAttestation)

	default:
		logger.Warn("call not recognized")
	}

}
