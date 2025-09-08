package settings

import (
	"os"
	"strconv"
	"time"
)

// Modes:
// - 0 production,
// - 1 local (no attestation)
var Mode = 1

func init() {
	if m, err := strconv.Atoi(os.Getenv("MODE")); err == nil {
		Mode = m
	} else {
		Mode = 1
	}
}

const MaxBIPS = 10000
const FtdcMinimumDataProvidersThreshold = float64(0.4)

const EncodingVersion = "1.0.0"

// Processor configuration
var QueuedActionsSleepTime = 100 * time.Millisecond

const ProxyConfigureServerPort = 5500
const ProxyTimeout = 2 * time.Second

const MaxInstructionSize = 100 * 1024 // 100 KB
const MaxActionSize = 1024 * 1024     // 1 MB

const GoogleCertLoc = "assets/google_confidential_space_root.crt"

const ExtensionServerPort = 8888
const ExtensionPort = 8889
