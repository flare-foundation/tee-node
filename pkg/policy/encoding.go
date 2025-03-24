package policy

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

type SigningPolicyPrefix struct {
	NumVoters          uint16
	RewardEpochId      uint32
	StartVotingRoundId uint32
	Threshold          uint16
	Seed               *big.Int
}

func EncodeSigningPolicy(policy *SigningPolicy) ([]byte, error) {
	// Validation
	if policy == nil {
		return nil, fmt.Errorf("signing policy is undefined")
	}
	if len(policy.Voters) != len(policy.Weights) {
		return nil, fmt.Errorf("voters and weights length mismatch")
	}
	if len(policy.Voters) > 65535 { // 2^16 - 1
		return nil, fmt.Errorf("too many signers")
	}

	// Validate reward epoch ID
	if policy.RewardEpochId > 16777215 { // 2^24 - 1
		return nil, fmt.Errorf("reward epoch id out of range: %d", policy.RewardEpochId)
	}

	// Validate seed
	seedBytes := policy.Seed.Bytes()
	if len(seedBytes) > 32 {
		return nil, fmt.Errorf("seed value too large")
	}

	// Calculate total size
	// 2(numVoters) + 3(rewardEpoch) + 4(startVoting) + 2(threshold) + 32(seed) + len(voters)*(20+2)
	totalSize := 43 + len(policy.Voters)*22

	// Create result buffer
	result := make([]byte, totalSize)
	pos := 0

	// Write number of voters (2 bytes)
	binary.BigEndian.PutUint16(result[pos:], uint16(len(policy.Voters)))
	pos += 2

	// Write reward epoch ID (3 bytes)
	result[pos] = byte(policy.RewardEpochId >> 16)
	result[pos+1] = byte(policy.RewardEpochId >> 8)
	result[pos+2] = byte(policy.RewardEpochId)
	pos += 3

	// Write start voting round ID (4 bytes)
	binary.BigEndian.PutUint32(result[pos:], policy.StartVotingRoundId)
	pos += 4

	// Write threshold (2 bytes)
	binary.BigEndian.PutUint16(result[pos:], policy.Threshold)
	pos += 2

	// Write seed (32 bytes, pad if necessary)
	copy(result[pos+32-len(seedBytes):pos+32], seedBytes)
	pos += 32

	// Write voters and weights
	for i := 0; i < len(policy.Voters); i++ {
		// Write voter address (20 bytes)
		copy(result[pos:], policy.Voters[i][:])
		pos += 20

		// Write weight (2 bytes)
		binary.BigEndian.PutUint16(result[pos:], policy.Weights[i])
		pos += 2
	}

	return result, nil
}

func decodeSigningPolicyPrefix(data []byte) (*SigningPolicyPrefix, error) {
	if len(data) < 64 {
		return nil, errors.New("insufficient data length")
	}

	prefix := &SigningPolicyPrefix{}

	// Number of voters (2 bytes)
	prefix.NumVoters = binary.BigEndian.Uint16(data[0:2])

	// Reward epoch ID (3 bytes)
	// Need to handle 3 bytes specially since Go doesn't have uint24
	prefix.RewardEpochId = uint32(data[2])<<16 |
		uint32(data[3])<<8 |
		uint32(data[4])

	// Start voting round ID (4 bytes)
	prefix.StartVotingRoundId = binary.BigEndian.Uint32(data[5:9])

	// Threshold (2 bytes)
	prefix.Threshold = binary.BigEndian.Uint16(data[9:11])

	// Seed (32 bytes)
	prefix.Seed = new(big.Int).SetBytes(data[11:43])

	return prefix, nil
}

func decodeSignersAndWeights(data []byte) ([]common.Address, []uint16, error) {
	// Convert bytes to hex string without 0x prefix
	hexStr := hex.EncodeToString(data)

	// Calculate number of signer+weight pairs
	// Each pair is 44 hex chars (40 for address + 4 for weight)
	if len(hexStr)%44 != 0 {
		return nil, nil, fmt.Errorf("invalid data length")
	}
	numSigners := len(hexStr) / 44

	voters := make([]common.Address, numSigners)
	weights := make([]uint16, numSigners)

	for i := 0; i < numSigners; i++ {
		// Get position in hex string
		pos := i * 44

		// Extract address (40 hex chars)
		addressHex := "0x" + hexStr[pos:pos+40]
		voters[i] = common.HexToAddress(addressHex)

		// Extract weight (4 hex chars)
		weightHex := hexStr[pos+40 : pos+44]
		weightInt, err := strconv.ParseUint(weightHex, 16, 16)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid weight hex: %s", weightHex)
		}
		weights[i] = uint16(weightInt)
	}

	return voters, weights, nil
}

func DecodeSigningPolicy(data []byte) (*SigningPolicy, error) {
	// First decode the prefix (the first 43 bytes)
	prefix, err := decodeSigningPolicyPrefix(data)
	if err != nil {
		return nil, err
	}

	// Calculate expected length
	// 64 bytes prefix + (numVoters-1)*(20+2) bytes for remaining voters/weights
	expectedLen := 43 + int(prefix.NumVoters)*(20+2)
	if len(data) < expectedLen {
		return nil, fmt.Errorf("insufficient data length: got %d, want %d", len(data), expectedLen)
	}

	voters, weights, err := decodeSignersAndWeights(data[43:])
	if err != nil {
		return nil, err
	}

	// Initialize result structure
	policy := &SigningPolicy{
		RewardEpochId:      prefix.RewardEpochId,
		StartVotingRoundId: prefix.StartVotingRoundId,
		Threshold:          prefix.Threshold,
		Seed:               *prefix.Seed,
		Voters:             voters,
		Weights:            weights,
	}

	return policy, nil
}

type SigningPolicy struct {
	RewardEpochId      uint32           `json:"rewardEpochId"`
	StartVotingRoundId uint32           `json:"startVotingRoundId"`
	Threshold          uint16           `json:"threshold"`
	Seed               big.Int          `json:"seed"`
	Voters             []common.Address `json:"voters"`
	Weights            []uint16         `json:"weights"`
}

func HexToBytes(hexStr string) ([]byte, error) {

	// Remove 0x prefix if present
	hexStr = strings.TrimPrefix(hexStr, "0x")

	if len(hexStr) == 0 {
		return []byte{}, nil // All zeros
	}

	// Ensure even length
	if len(hexStr)%2 != 0 {
		return nil, fmt.Errorf("invalid hex string length: %v", len(hexStr))
	}

	// Convert hex to bytes
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %v", err)
	}

	return bytes, nil
}
