package instructionservice

import (
	api "tee-node/api/types"
	"tee-node/internal/service/instructionservice/signingservice"
	"tee-node/internal/service/instructionservice/walletsservice"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// * ----- REG OpType ----- * //

// TODO: Implement this service and APIs
func handleRegPostRequest(instructionData *api.InstructionData) ([]byte, error) {
	switch instructionData.OpCommand {
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

// * ----- WALLET OpType ----- * //

func handleWalletPostRequest(instructionData *api.InstructionData, signatures [][]byte) ([]byte, error) {
	switch instructionData.OpCommand {

	case "KEY_GENERATE":
		return []byte{}, walletsservice.NewWallet(instructionData)

	case "KEY_DELETE":
		return []byte{}, walletsservice.DeleteWallet(instructionData)

	case "KEY_MACHINE_BACKUP":
		return []byte{}, walletsservice.SplitWallet(instructionData, signatures)

	case "KEY_MACHINE_RESTORE":
		return []byte{}, walletsservice.RecoverWallet(instructionData, signatures)

	case "KEY_MACHINE_BACKUP_REMOVE":
		return walletsservice.KeyMachineBackupRemove(instructionData)

	case "KEY_CUSTODIAN_BACKUP":
		return walletsservice.KeyCustodianBackup(instructionData)

	case "KEY_CUSTODIAN_RESTORE":
		return walletsservice.KeyCustodianRestore(instructionData)

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for WALLET OpType")
	}

}

// * ----- XRP OpType ----- * //

// TODO: Implement this service and APIs
func handleXrpPostRequest(instructionData *api.InstructionData) ([]byte, error) {

	switch instructionData.OpCommand {
	case "PAY":
		return signingservice.SignPaymentTransaction(instructionData)

	case "REISSUE":
		return signingservice.XrpReissue(instructionData)

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for XRP OpType")
	}
}

func handleBtcPostRequest(instructionData *api.InstructionData) ([]byte, error) {
	switch instructionData.OpCommand {
	case "PAY":
		return nil, status.Error(codes.Unimplemented, "BTC PAY command not implemented yet")

	case "REISSUE":
		return nil, status.Error(codes.Unimplemented, "BTC REISSUE command not implemented yet")

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for BTC OpType")

	}
}

func handleFdcPostRequest(instructionData *api.InstructionData) ([]byte, error) {
	switch instructionData.OpCommand {
	case "PROVE":
		return nil, status.Error(codes.Unimplemented, "FDC PROVE command not implemented yet")

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for FDC OpType")
	}
}
