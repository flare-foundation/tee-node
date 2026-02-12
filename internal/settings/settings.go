package settings

import (
	"os"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/convert"
)

func init() {
	if m, err := strconv.Atoi(os.Getenv("MODE")); err == nil {
		Mode = m
	}

	if logLevelEnv := os.Getenv("LOG_LEVEL"); len(logLevelEnv) != 0 {
		LogLevel = logLevelEnv
	}

	if port, err := strconv.Atoi(os.Getenv("CONFIG_PORT")); err == nil && port > 0 && port <= 65535 {
		ConfigPort = port
	}

	if port, err := strconv.Atoi(os.Getenv("SIGN_PORT")); err == nil && port > 0 && port <= 65535 {
		SignPort = port
	}

	if port, err := strconv.Atoi(os.Getenv("EXTENSION_PORT")); err == nil && port > 0 && port <= 65535 {
		ExtensionPort = port
	}
}

const EncodingVersion = "1.0.0"

// Processor configuration
var QueuedActionsSleepTime = 100 * time.Millisecond

const ProxyTimeout = 2 * time.Second

const (
	MaxInstructionSize = 100 * 1024  // 100 KB
	MaxActionSize      = 1024 * 1024 // 1 MB
)

const GoogleCertLoc = "assets/google_confidential_space_root.crt"

const (
	SetProxyURLEndpoint = "/proxy"
	ProxyURLEnvVar      = "PROXY_URL"

	SetInitialOwnerEndpoint = "/initial-owner"
	InitialOwnerEnvVar      = "INITIAL_OWNER"

	SetExtensionIDEndpoint = "/extension-id"
	ExtensionIDEnvVar      = "EXTENSION_ID"
)

var (
	// Modes:
	// - 0 production,
	// - 1 local (no attestation)
	Mode     = 1
	LogLevel = "FATAL"

	ConfigPort    = 5500 // For node configuration.
	SignPort      = 8888 // For signing action results received from extensions.
	ExtensionPort = 8889 // Extension's port that accepts actions.

	TestPlatform, _ = convert.StringToCommonHash("TEST_PLATFORM")
	TestCodeHash    = common.HexToHash("194844cf417dde867073e5ab7199fa4d21fd82b5dbe2bdea8b3d7fc18d10fdc2")
	TestCodeHash1   = common.HexToHash("a9919519b88a4659e8811433094e14a2a2c2939493a328e9db8e4d3bb71eb85e")

	DefaultExtensionID = common.MaxHash
)
