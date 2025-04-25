package instructionservice

import (
	"tee-node/pkg/requests"
	"tee-node/pkg/service/instructionservice/policyinstruction"
	"tee-node/pkg/service/instructionservice/signinginstruction"
	"tee-node/pkg/service/instructionservice/walletsinstruction"
	"tee-node/pkg/utils"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// * ----- REG OpType ----- * //

// TODO: Implement this service and APIs
func handleRegPostRequest(requestCounter *requests.RequestCounter) ([]byte, error) {
	switch utils.OpHashToString(requestCounter.Request.OPCommand) {
	case "AVAILABILITY_CHECK":
		return nil, status.Error(codes.Unimplemented, "REG AVAILABILITY_CHECK command not implemented yet")

	case "TO_PAUSE_FOR_UPGRADE":
		return nil, status.Error(codes.Unimplemented, "REG TO_PAUSE_FOR_UPGRADE command not implemented yet")

	case "REPLICATE_FROM":
		return nil, status.Error(codes.Unimplemented, "REG REPLICATE_FROM command not implemented yet")

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for WALLET OpType")
	}
}

func handlePolicyPostRequest(requestCounter *requests.RequestCounter) ([]byte, error) {
	switch utils.OpHashToString(requestCounter.Request.OPCommand) {
	case "UPDATE_POLICY":
		return []byte{}, policyinstruction.UpdatePolicy(requestCounter.Request)

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for WALLET OpType")
	}
}

// * ----- WALLET OpType ----- * //

func handleWalletPostRequest(requestCounter *requests.RequestCounter) ([]byte, error) {
	switch utils.OpHashToString(requestCounter.Request.OPCommand) {

	case "KEY_GENERATE":
		return []byte{}, walletsinstruction.NewWallet(requestCounter.Request)

	case "KEY_DELETE":
		return []byte{}, walletsinstruction.DeleteWallet(requestCounter.Request)

	case "KEY_DATA_PROVIDER_RESTORE_INIT":
		return walletsinstruction.KeyDataProviderRestoreInit(requestCounter.Request)

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for WALLET OpType")
	}
}

// * ----- XRP OpType ----- * //

// TODO: Implement this service and APIs
func handleXrpPostRequest(requestCounter *requests.RequestCounter) ([]byte, error) {

	switch utils.OpHashToString(requestCounter.Request.OPCommand) {
	case "PAY":
		return signinginstruction.SignPaymentTransaction(requestCounter.Request)

	case "REISSUE":
		return signinginstruction.XrpReissue(requestCounter.Request)

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for XRP OpType")
	}
}

func handleBtcPostRequest(requestCounter *requests.RequestCounter) ([]byte, error) {
	switch utils.OpHashToString(requestCounter.Request.OPCommand) {
	case "PAY":
		return nil, status.Error(codes.Unimplemented, "BTC PAY command not implemented yet")

	case "REISSUE":
		return nil, status.Error(codes.Unimplemented, "BTC REISSUE command not implemented yet")

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for BTC OpType")

	}
}

func handleFdcPostRequest(requestCounter *requests.RequestCounter) ([]byte, error) {
	switch utils.OpHashToString(requestCounter.Request.OPCommand) {
	case "PROVE":
		return nil, status.Error(codes.Unimplemented, "FDC PROVE command not implemented yet")

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for FDC OpType")
	}
}
