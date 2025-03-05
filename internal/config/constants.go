package config

var InitialPolicyHash = "6c5d823aa3ecf8e2a00f7bad8b03d6e4557de9ac7be7c5d8408047f5a31f4fd1"

// var InitialPolicyBytesHex = "" // TODO: Add the initial policy bytes here as a hex string

const XRP_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

// Modes:
// - 0 production,
// - 1 local (no attestation)
const Mode = 1

// The number of latest policies that are considered active enough to be used for signing
const ACTIVE_POLICY_COUNT = 3
