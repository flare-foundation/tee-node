package config

var InitialPolicyHash = "6c5d823aa3ecf8e2a00f7bad8b03d6e4557de9ac7be7c5d8408047f5a31f4fd1"

// var InitialPolicyBytesHex = "" // TODO: Add the initial policy bytes here as a hex string

// Modes:
// - 0 production,
// - 1 local (no attestation)
var Mode = 1

// The number of latest policies that are considered active enough to be used for signing
const ACTIVE_POLICY_COUNT = 3

// Hardcoded configuration for operations and subcommands
var InstructionOperations = map[string][]string{
	"REG": {
		"AVAILABILITY_CHECK",
		"TO_PAUSE_FOR_UPGRADE",
		"REPLICATE_FROM",
	},
	"POLICY": {
		"UPDATE_POLICY",
	},
	"WALLET": {
		"KEY_GENERATE",
		"KEY_DELETE",
		"KEY_MACHINE_BACKUP",
		"KEY_MACHINE_RESTORE",
		"KEY_MACHINE_BACKUP_REMOVE",
		"KEY_CUSTODIAN_BACKUP",
		"KEY_CUSTODIAN_RESTORE",
	},
	"XRP": {
		"PAY",
		"REISSUE",
	},
	"BTC": {
		"PAY",
		"REISSUE",
	},
	"FDC": {
		"PROVE",
	},
}

type ServiceMethod struct {
	Service string
	Method  string
}

// todo: remove when this info not needed
var ServiceMethodMapping = map[string]map[string]ServiceMethod{
	"REG": {
		"AVAILABILITY_CHECK":   {"RegistryService", "CheckAvailability"},
		"TO_PAUSE_FOR_UPGRADE": {"RegistryService", "PauseForUpgrade"},
		"REPLICATE_FROM":       {"RegistryService", "ReplicateData"},
	},
	"WALLET": {
		"KEY_GENERATE":              {"WalletService", "GenerateKey"},
		"KEY_DELETE":                {"WalletService", "DeleteKey"},
		"KEY_MACHINE_BACKUP":        {"WalletService", "BackupMachineKey"},
		"KEY_MACHINE_RESTORE":       {"WalletService", "RestoreMachineKey"},
		"KEY_MACHINE_BACKUP_REMOVE": {"WalletService", "RemoveMachineBackup"},
		"KEY_CUSTODIAN_BACKUP":      {"CustodianService", "BackupCustodianKey"},
		"KEY_CUSTODIAN_RESTORE":     {"CustodianService", "RestoreCustodianKey"},
	},
	"XRP": {
		"PAY":     {"PaymentService", "ProcessXRPPayment"},
		"REISSUE": {"PaymentService", "ReissueXRP"},
	},
	"BTC": {
		"PAY":     {"PaymentService", "ProcessBTCPayment"},
		"REISSUE": {"PaymentService", "ReissueBTC"},
	},
	"FDC": {
		"PROVE": {"FDCService", "ProveOwnership"},
	},
}
