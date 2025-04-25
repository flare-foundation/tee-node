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

const CHECK_GARBAGE_COLLECTION_INTERVAL = 5 * time.Second        // This is how often we check if any requests were completed
const REQUEST_GARBAGE_COLLECTION_INTERVAL = 30 * time.Second     // This is how long we wait before removing instruction request that were not completed
const PENDING_BACKUP_GARBAGE_COLLECTION_INTERVAL = 1 * time.Hour // This is how long we wait before removing backup collection that wes not completed

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
		"KEY_DATA_PROVIDER_RESTORE_INIT",
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
	MaxOriginalMessageSize:           50 * 1024,  // 50KB
	MaxAdditionalFixedMessageSize:    100 * 1024, // 100KB
	MaxAdditionalVariableMessageSize: 50 * 1024,  // 50KB
}

// Todo: We should define the size limits for each operation
var MaxRequestSize = map[string]map[string]MessageSizeContraint{
	"REG": {
		"AVAILABILITY_CHECK":   standardSizeConstraint,
		"TO_PAUSE_FOR_UPGRADE": standardSizeConstraint,
		"REPLICATE_FROM":       standardSizeConstraint,
	},
	"WALLET": {
		"KEY_GENERATE":                   standardSizeConstraint,
		"KEY_DELETE":                     standardSizeConstraint,
		"KEY_DATA_PROVIDER_RESTORE_INIT": standardSizeConstraint,
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

const ThresholdSetByPolicy = -1

// Threshold needed to execute an instruction (-1 means defined by the signing policy)
var Thresholds = map[string]map[string]int{
	"REG": {
		"AVAILABILITY_CHECK":   ThresholdSetByPolicy,
		"TO_PAUSE_FOR_UPGRADE": ThresholdSetByPolicy,
		"REPLICATE_FROM":       ThresholdSetByPolicy,
	},
	"WALLET": {
		"KEY_GENERATE":                   ThresholdSetByPolicy,
		"KEY_DELETE":                     ThresholdSetByPolicy,
		"KEY_DATA_PROVIDER_RESTORE_INIT": ThresholdSetByPolicy,
	},
	"POLICY": {
		"UPDATE_POLICY": 0,
	},
	"XRP": {
		"PAY":     ThresholdSetByPolicy,
		"REISSUE": ThresholdSetByPolicy,
	},
	"BTC": {
		"PAY":     ThresholdSetByPolicy,
		"REISSUE": ThresholdSetByPolicy,
	},
	"FDC": {
		"PROVE": ThresholdSetByPolicy,
	},
}

const NormalizationConstant = 4000
const DataProvidersBackupThreshold = 2666

func WeightsNormalization(weights []uint16) []uint16 {
	sum := uint16(0)
	for _, weight := range weights {
		sum += weight
	}

	normalizedWeighs := make([]uint16, len(weights))

	for i, weight := range weights {
		normalizedWeighs[i] = uint16((int(weight) * NormalizationConstant) / int(sum))
	}

	return normalizedWeighs
}
