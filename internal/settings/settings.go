package settings

import (
	"os"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/convert"
)

// Modes:
// - 0 production,
// - 1 local (no attestation)
var Mode int
var LogLevel string

func init() {
	if m, err := strconv.Atoi(os.Getenv("MODE")); err == nil {
		Mode = m
	} else {
		Mode = 1
	}
	if logLevelEnv := os.Getenv("LOG_LEVEL"); len(logLevelEnv) != 0 {
		LogLevel = logLevelEnv
	} else {
		LogLevel = "FATAL"
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
	ExtensionServerPort = 8888
	ExtensionPort       = 8889
)

const (
	ConfigureServerPort = 5500

	SetProxyURLEndpoint = "/proxy"
	ProxyURLEnvVar      = "PROXY_URL"

	SetInitialOwnerEndpoint = "/initial-owner"
	InitialOwnerEnvVar      = "INITIAL_OWNER"

	SetExtensionIDEndpoint = "/extension-id"
	ExtensionIDEnvVar      = "EXTENSION_ID"
)

var (
	TestPlatform, _ = convert.StringToCommonHash("TEST_PLATFORM")
	TestCodeHash    = common.HexToHash("194844cf417dde867073e5ab7199fa4d21fd82b5dbe2bdea8b3d7fc18d10fdc2")
	TestCodeHash1   = common.HexToHash("a9919519b88a4659e8811433094e14a2a2c2939493a328e9db8e4d3bb71eb85e")

	DefaultExtensionID = common.MaxHash
)
