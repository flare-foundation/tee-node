package requests

import (
	"encoding/hex"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"golang.org/x/exp/slices"
)

// instructionIdToHash handles the mapping needed to find all the instructions
// based on instruction Id
var instructionIdToHash = InitInstructionIdToHashes()

type InstructionIdToHashes struct {
	Map map[common.Hash][]string

	sync.Mutex
}

func InitInstructionIdToHashes() *InstructionIdToHashes {
	return &InstructionIdToHashes{Map: make(map[common.Hash][]string)}
}

func GetHashesWithId(instructionId string) ([]string, bool) {
	instructionIdToHash.Lock()
	defer instructionIdToHash.Unlock()

	requestsWithId, ok := instructionIdToHash.Map[common.HexToHash(instructionId)]
	if !ok {
		return nil, false
	}
	requestsWithIdCopy := make([]string, len(requestsWithId))
	copy(requestsWithIdCopy, requestsWithId)

	return requestsWithIdCopy, true
}

func ProcessInstructionIdMapping(instructionData *instruction.DataFixed) {
	instructionIdToHash.Lock()
	defer instructionIdToHash.Unlock()

	if _, ok := instructionIdToHash.Map[instructionData.InstructionID]; !ok {
		instructionIdToHash.Map[instructionData.InstructionID] = make([]string, 0)
	}

	hash, err := instructionData.HashFixed()
	if err != nil {
		log.Error("Error hashing instruction data", "error", err)
		return
	}
	instructionHash := hex.EncodeToString(hash[:])

	// If the instruction hash is already in the list, we don't need to add it again
	if slices.Contains(instructionIdToHash.Map[instructionData.InstructionID], instructionHash) {
		return
	}

	instructionIdToHash.Map[instructionData.InstructionID] = append(instructionIdToHash.Map[instructionData.InstructionID], instructionHash)
}
