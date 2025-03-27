package config

import "time"

var InitialPolicyHash = "6c5d823aa3ecf8e2a00f7bad8b03d6e4557de9ac7be7c5d8408047f5a31f4fd1"

// var InitialPolicyBytesHex = "" // TODO: Add the initial policy bytes here as a hex string

// Modes:
// - 0 production,
// - 1 local (no attestation)
var Mode = 1

// todo: set this correctly
const MAX_PENDING_REQUESTS = 100

const CHECK_GARBAGE_COLLECTION_INTERVAL = 5 * time.Second    // This is how often we check if any requests were completed
const REQUEST_GARBAGE_COLLECTION_INTERVAL = 30 * time.Second // This is how long we wait before removing request that were not completed

const MAX_COMPLETED_REQUESTS_COUNT = 10_000 // The number of completed requests(voting processes) we are storing at a time

const CLEAR_PENDING_COUNT = 10_000 // The number of new request proposals (completed or uncompleted) before we clear the pending requests
const LIMIT_HIT_COUNT = 35         // The number of validators that must hit the limit before we clear the pending requests. This is in case of some FDC edge cases, where many validators could hit the limit at the same time
// The number of latest policies that are considered active enough to be used for signing

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

const MaxInstructionFieldSize = 64 // All fields apart from the message should be less than this
const MaxChallengeSize = 64
const MaxSignatureSize = 65 // The size of the signature

type MessageSizeContraint struct {
	MaxOriginalMessageSize           int
	MaxAdditionalFixedMessageSize    int
	MaxAdditionalVariableMessageSize int
}

// TODO: This is some base limit that can be overridden by specific opType and opCommand
var standardSizeConstraint = MessageSizeContraint{
	MaxOriginalMessageSize:           50 * 1024, // 50KB
	MaxAdditionalFixedMessageSize:    50 * 1024, // 50KB
	MaxAdditionalVariableMessageSize: 50 * 1024, // 50KB
}

// Todo: We should define the size limits for each operation
var MaxRequestSize = map[string]map[string]MessageSizeContraint{
	"REG": {
		"AVAILABILITY_CHECK":   standardSizeConstraint,
		"TO_PAUSE_FOR_UPGRADE": standardSizeConstraint,
		"REPLICATE_FROM":       standardSizeConstraint,
	},
	"WALLET": {
		"KEY_GENERATE":              standardSizeConstraint,
		"KEY_DELETE":                standardSizeConstraint,
		"KEY_MACHINE_BACKUP":        standardSizeConstraint,
		"KEY_MACHINE_RESTORE":       standardSizeConstraint,
		"KEY_MACHINE_BACKUP_REMOVE": standardSizeConstraint,
		"KEY_CUSTODIAN_BACKUP":      standardSizeConstraint,
		"KEY_CUSTODIAN_RESTORE":     standardSizeConstraint,
	},
	"POLICY": {
		"UPDATE_POLICY": standardSizeConstraint,
	},
	"XRP": {
		"PAY":     standardSizeConstraint,
		"REISSUE": standardSizeConstraint,
	},
	"BTC": {
		"PAY":     standardSizeConstraint,
		"REISSUE": standardSizeConstraint,
	},
	"FDC": {
		"PROVE": standardSizeConstraint,
	},
}
