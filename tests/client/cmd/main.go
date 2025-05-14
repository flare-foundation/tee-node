package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"os"
	"strconv"

	"tee-node/api/types"
	api "tee-node/api/types"

	attestationserver "tee-node/pkg/attestation"
	policyserver "tee-node/pkg/policy"
	utilsserver "tee-node/pkg/utils"
	utils "tee-node/tests"

	"tee-node/tests/client/config"
	"tee-node/tests/client/policy"
	"tee-node/tests/client/xrpl"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/alexflint/go-arg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/database"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	commonpayment "github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
)

var args struct {
	Call          string
	Arg1          string
	Provider      int
	WalletId      string
	KeyId         string
	BackupId      string
	PubKey        string
	TeeId         string
	InstructionId string
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
		voters, privKeys, _ := utils.GenerateRandomVoters(numVoters)

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
		params := &policy.PolicyHistoryParams{RelayContractAddress: common.HexToAddress(config.Chain.RelayContractAddress),
			FlareSystemManagerContractAddress: common.HexToAddress(config.Chain.FlareSystemManagerContractAddress),
			FlareVoterRegistryContractAddress: common.HexToAddress(config.Chain.FlareVoterRegistryContractAddress),
		}

		policies, signatures, err := policy.FetchPolicyHistory(ctx, params, db)
		if err != nil {
			log.Fatalf("could not fetch policy: %v", err)
		}
		activePolicyRewardEpoch := int(policies[len(policies)-1].RewardEpochId.Int64())
		minBlockNum, maxBlockNum, err := policy.FetchVoterRegisteredBlocksInfo(context.Background(), params, db, activePolicyRewardEpoch)
		if err != nil {
			log.Fatalf("could not fetch blocks info: %v", err)
		}
		pubKeysMap, err := policy.FetchVotersPublicKeysMap(context.Background(), params, db, minBlockNum, maxBlockNum, activePolicyRewardEpoch)
		if err != nil {
			log.Fatalf("could not fetch public keys: %v", err)
		}

		action, err := policy.CreateInitializePolicyAction(policies, signatures, pubKeysMap)
		if err != nil {
			log.Fatalf("could not create signing action: %v", err)
		}

		_, err = utils.Post[api.ActionResponse](config.Server.Host+"/action", action)
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
		pubKeys := make([]api.ECDSAPublicKey, len(providers.PrivKeys))
		for i, voter := range providers.PrivKeys {
			pubKeys[i] = api.PubKeyToBytes(&voter.PublicKey)
		}

		epochId, randSeed := uint32(1), int64(12345)
		initialPolicy := utils.GenerateRandomPolicyData(epochId, providers.Voters, randSeed)
		initialPolicyBytes, err := policyserver.EncodeSigningPolicy(&initialPolicy)
		if err != nil {
			log.Fatalf("%v", err)
		}

		numPolicies := 5
		policySignaturesArray, err := utils.GenerateRandomMultiSignedPolicyArray(epochId, randSeed, providers.Voters, providers.PrivKeys, numPolicies)
		if err != nil {
			log.Fatalf("could not generate random policy policy: %v", err)
		}

		req := &api.InitializePolicyRequest{
			InitialPolicyBytes:     initialPolicyBytes,
			NewPolicyRequests:      policySignaturesArray,
			LatestPolicyPublicKeys: pubKeys,
		}

		action, err := utils.BuildMockInitializePolicyAction(req)
		if err != nil {
			log.Fatalf("could not build mock initialize policy action: %v", err)
		}
		_, err = utils.Post[api.InitializePolicyResponse](config.Server.Host+"/action", action)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		latestPolicy := req.NewPolicyRequests[len(req.NewPolicyRequests)-1]
		decodedPolicy, err := policyserver.DecodeSigningPolicy(latestPolicy.PolicyBytes)
		if err != nil {
			log.Fatalf("could not decode policy: %v", err)
		}
		logger.Infof("initialized policies. Active EpochID: %v", decodedPolicy.RewardEpochId)

	case "new_wallet":
		providerPrivKey, err := getProviderPrivKey(args.Provider)
		if err != nil {
			log.Fatalf("could not get provider private key: %v", err)
		}
		keyIdParsed, err := strconv.ParseUint(args.KeyId, 10, 32)
		if err != nil {
			log.Fatalf("could not parse key id: %v", err)
		}
		adminPrivKey := crypto.ToECDSAUnsafe(big.NewInt(1).Bytes())
		adminPubKey := wallet.PublicKey(types.PubKeyToBytes(&adminPrivKey.PublicKey))

		originalMessage := wallet.ITeeWalletKeyManagerKeyGenerate{
			TeeId:              common.HexToAddress(args.TeeId),
			WalletId:           common.HexToHash(args.WalletId),
			KeyId:              keyIdParsed,
			OpType:             utilsserver.StringToOpHash("WALLET"),
			OpTypeConstants:    make([]byte, 0),
			AdminsPublicKeys:   []wallet.PublicKey{adminPubKey},
			AdminsThreshold:    1,
			Cosigners:          make([]common.Address, 0),
			CosignersThreshold: 0,
		}
		originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[wallet.KeyGenerate]}.Pack(originalMessage)
		if err != nil {
			log.Fatalf("could not pack original message: %v", err)
		}

		instruction, err := utils.BuildMockInstruction("WALLET",
			"KEY_GENERATE",
			originalMessageEncoded,
			interface{}(nil),
			providerPrivKey,
			common.HexToAddress(args.TeeId),
			args.InstructionId,
			args.RewardEpochId,
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		resp, err := utils.Post[api.InstructionResponse](config.Server.Host+"/instruction", instruction)
		if err != nil {
			log.Fatalf("could not create a new wallet: %v", err)
		}

		logger.Infof("created a wallet: finalized:%v", resp.Finalized)

	case "wallet_info":
		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalf("%v", err)
		}

		keyIdBig, err := strconv.ParseUint(args.KeyId, 10, 32)
		if err != nil {
			log.Fatalf("could not parse key id: %v", err)
		}

		req := &api.WalletInfoRequest{
			WalletId:  common.HexToHash(args.WalletId),
			KeyId:     keyIdBig,
			Challenge: hex.EncodeToString(nonceBytes),
		}
		accInfoResp, err := utils.Post[api.WalletInfoResponse](config.Server.Host+"/wallet", req)
		if err != nil {
			log.Fatalf("could not get wallet info: %v", err)
		}
		logger.Infof("EthAddress: %s, XrpAddress: %s, PublicKey: %s, Attestation Token %s",
			accInfoResp.EthAddress, accInfoResp.XrpAddress, hex.EncodeToString(accInfoResp.PublicKey.X[:])+hex.EncodeToString(accInfoResp.PublicKey.Y[:]), accInfoResp.Token)

	case "node_info":
		req := &api.GetNodeInfoRequest{Nonce: string(nonceBytes)}
		resp, err := utils.Post[api.GetNodeInfoResponse](config.Server.Host+"/info", req)
		if err != nil {
			log.Fatalf("could not get attestation: %v", err)
		}

		log.Println("TOKEN", resp.Token)

		teeId := resp.Data.TeeId

		logger.Infof("TeeId: %v", teeId)
		logger.Infof("PubKey: %s", hex.EncodeToString(resp.Data.PublicKey.X[:])+hex.EncodeToString(resp.Data.PublicKey.Y[:]))

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

		payment, err := xrpl.ConstructPaymentTransaction(paymentFields.Amount,
			paymentFields.Fee,
			paymentFields.SpenderAccount,
			paymentFields.DestinationAccount,
			paymentFields.Sequence,
			paymentFields.LastLedgerSeq)
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

		keyIdBig, err := strconv.ParseUint(args.KeyId, 10, 32)
		if err != nil {
			log.Fatalf("could not parse key id: %v", err)
		}

		// ---------- Sign the message request ---------- //

		originalMessage := commonpayment.ITeePaymentsPaymentInstructionMessage{
			WalletId:           common.HexToHash(args.WalletId),
			SenderAddress:      "0x123",
			RecipientAddress:   "0x456",
			Amount:             big.NewInt(1000000000),
			PaymentReference:   [32]byte{},
			Nonce:              uint64(0),
			SubNonce:           uint64(0),
			MaxFee:             big.NewInt(0),
			MaxFeeTolerancePPM: uint32(0),
			BatchEndTs:         uint64(0),
		}
		originalMessageEncoded, err := abi.Arguments{commonpayment.MessageArguments[commonpayment.Pay]}.Pack(originalMessage)
		if err != nil {
			log.Fatalf("could not pack original message: %v", err)
		}

		instruction, err := utils.BuildMockInstruction(
			"XRP",
			"PAY",
			originalMessageEncoded,
			api.SignPaymentAdditionalFixedMessage{
				PaymentHash: paymentHash,
				KeyId:       keyIdBig,
			},
			providerPrivKey,
			common.HexToAddress(args.TeeId),
			args.InstructionId,
			args.RewardEpochId,
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		// ---------- Send the transaction to the signing service ---------- //
		resp, err := utils.Post[api.InstructionResponse](config.Server.Host+"/instruction", instruction)
		if err != nil {
			log.Fatalf("could not sign payment transaction: %v", err)
		}

		logger.Info("Payment hash: %v", hex.EncodeToString(txHash))
		logger.Infof("sent request to SignPaymentTransaction, is ThresholdReached %v, Token %v", resp.Finalized, resp.Token)

	case "get_payment_signature":
		nonceBytes, _ := utilsserver.GenerateRandomBytes(32)

		req := &api.InstructionResultRequest{
			InstructionId: args.InstructionId,
			Challenge:     hex.EncodeToString(nonceBytes),
		}

		resp, err := utils.Post[api.InstructionResultResponse](config.Server.Host+"/instruction/result", req)
		if err != nil {
			log.Fatalf("could not get the payment signature : %v", err)
		}

		var paymentSigResponse api.GetPaymentSignatureResponse
		err = json.Unmarshal(resp.Data, &paymentSigResponse)
		if err != nil {
			log.Fatalf("could not decode the payment signature : %v", err)
		}

		txnSignature := hex.EncodeToString(paymentSigResponse.TxnSignature)
		signingPubKey := hex.EncodeToString(paymentSigResponse.SigningPubKey)

		logger.Infof("sent request to GetPaymentSignature, is Account %v, TxnSignature %s, PublicKey %s, Token %v",
			paymentSigResponse.Account, txnSignature, signingPubKey, resp.Token)

	case "save_wallet_backup":
		nonceBytes, _ := utilsserver.GenerateRandomBytes(32)

		keyIdParsed, err := strconv.ParseUint(args.KeyId, 10, 32)
		if err != nil {
			log.Fatalf("could not parse key id: %v", err)
		}

		pubKey, err := hex.DecodeString(args.PubKey)
		if err != nil {
			log.Fatalf("could not parse public key: %v", err)
		}
		req := api.WalletGetBackupRequest{
			ITeeWalletBackupManagerKeyDataProviderRestore: wallet.ITeeWalletBackupManagerKeyDataProviderRestore{
				TeeId:         common.HexToAddress(args.TeeId),
				WalletId:      common.HexToHash(args.WalletId),
				KeyId:         keyIdParsed,
				OpType:        utilsserver.StringToOpHash("WALLET"),
				PublicKey:     pubKey,
				RewardEpochId: big.NewInt(int64(args.RewardEpochId)),
			},
			Challenge: hex.EncodeToString(nonceBytes),
		}
		backupResp, err := utils.Post[api.WalletGetBackupResponse](config.Server.Host+"/wallet/get-backup", req)
		if err != nil {
			log.Fatalf("could not get the payment signature : %v", err)
		}
		f, err := os.Create("tests/test_backup.json")
		if err != nil {
			log.Fatalf("%v", err)
		}
		_, err = f.Write(backupResp.WalletBackup)
		if err != nil {
			log.Fatalf("%v", err)
		}

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
