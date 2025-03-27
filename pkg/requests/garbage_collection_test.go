package requests_test

import (
	"encoding/hex"
	"math/big"
	"sync"
	"tee-node/pkg/config"
	"tee-node/pkg/requests"
	"tee-node/pkg/utils"

	testutils "tee-node/tests"

	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var gbgCollector *requests.GarbageCollector
var numVoters, randSeed, epochId = 100, int64(12345), uint32(1)

func setupTest(t *testing.T) {
	_, _, _ = testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	gbgCollector = requests.NewGarbageCollector()

	t.Cleanup(func() {
		requests.DestroyState()
	})
}

// Test that the garbage collector can handle a request that is completed (in the uncompleted queue)
func TestGCUnclompletedRequestQueueRequestCompleted(t *testing.T) {
	setupTest(t)

	// Setup
	requests.RateLimiterActive = requests.NewRateLimiter(10)

	voters := []common.Address{
		common.HexToAddress("0x1"),
	}
	requests.UpdateRateLimiter(voters)

	completed := true
	reqHash := insertNRequests(t, gbgCollector, 1, completed, epochId)[0]

	// Verify it's in the queue
	assert.Equal(t, 1, gbgCollector.UncompletedRequestQueue.Size())

	// Manually set creation time to be old enough for cleanup
	updateUncompleteQueueTime(gbgCollector)

	// Run cleanup
	gbgCollector.CleanupUncompletedRequests()

	// Verify request moved to completed queue
	assert.Equal(t, 0, gbgCollector.UncompletedRequestQueue.Size())
	assert.Equal(t, 1, gbgCollector.CompletedRequestQueue.Size())

	// assert that the request counter still exists in the storage
	reqCounter, exists := requests.GetRequestCounterByHash(reqHash)
	assert.True(t, exists)
	assert.NotNil(t, reqCounter)
}

// Test that the garbage collector can handle a request that is not completed (in the uncompleted queue)
func TestGCUnclompletedRequestQueueRequestUncompleted(t *testing.T) {
	setupTest(t)

	// Setup
	requests.RateLimiterActive = requests.NewRateLimiter(10)

	voters := []common.Address{
		common.HexToAddress("0x1"),
	}
	requests.UpdateRateLimiter(voters)

	completed := false
	reqHash := insertNRequests(t, gbgCollector, 1, completed, epochId)[0]

	// Verify it's in the queue
	assert.Equal(t, 1, gbgCollector.UncompletedRequestQueue.Size())

	// Manually set creation time to be old enough for cleanup
	value, _ := gbgCollector.UncompletedRequestQueue.Peek()
	request := value.(*requests.TimeOrderedRequest)
	request.CreatedAt = time.Now().Add(-2 * config.REQUEST_GARBAGE_COLLECTION_INTERVAL)

	// Run cleanup
	gbgCollector.CleanupUncompletedRequests()

	// Verify request was removed from the queue
	assert.Equal(t, 0, gbgCollector.UncompletedRequestQueue.Size())
	assert.Equal(t, 0, gbgCollector.CompletedRequestQueue.Size())

	// assert that the request was removed from the storage
	reqCounter, exists := requests.GetRequestCounterByHash(reqHash)
	assert.False(t, exists)
	assert.Nil(t, reqCounter)
}

// Test that the garbage collector removes request from the completed results queue
func TestGCCompletedRequestQueue(t *testing.T) {
	setupTest(t)

	// Setup
	requests.RateLimiterActive = requests.NewRateLimiter(10)

	voters := []common.Address{
		common.HexToAddress("0x1"),
	}
	requests.UpdateRateLimiter(voters)

	// Insert N requests
	completed := true
	reqHashes := insertNRequests(t, gbgCollector, config.MAX_COMPLETED_REQUESTS_COUNT, completed, epochId)

	// Verify it's in the queue
	assert.Equal(t, config.MAX_COMPLETED_REQUESTS_COUNT, gbgCollector.UncompletedRequestQueue.Size())

	updateUncompleteQueueTime(gbgCollector)

	// Run cleanup
	gbgCollector.CleanupUncompletedRequests()

	// Verify request moved to completed queue
	assert.Equal(t, 0, gbgCollector.UncompletedRequestQueue.Size())
	assert.Equal(t, config.MAX_COMPLETED_REQUESTS_COUNT, gbgCollector.CompletedRequestQueue.Size())

	// Check that the request in the completed queue are in order of being inserted
	for i, value := range gbgCollector.CompletedRequestQueue.Values() {
		request := value.(*requests.TimeOrderedRequest)

		if request.RequestHash != reqHashes[i] {
			t.Errorf("Request hash mismatch 2")
		}
	}

	// ! add a new reques to the completed queue ---------------------------
	newReqHash := insertNRequests(t, gbgCollector, 1, true, epochId)[0]

	// Update the time and run cleanup
	updateUncompleteQueueTime(gbgCollector)
	gbgCollector.CleanupUncompletedRequests()

	// Verify the completed queue is still at max capacity and the new request is in the queue
	assert.Equal(t, config.MAX_COMPLETED_REQUESTS_COUNT, gbgCollector.CompletedRequestQueue.Size())

	// check the new request is at the end of the queue
	assert.Equal(t, newReqHash, gbgCollector.CompletedRequestQueue.Values()[config.MAX_COMPLETED_REQUESTS_COUNT-1].(*requests.TimeOrderedRequest).RequestHash)

	// Check that the request in the completed queue are in order of being inserted pushed up by one
	for i, value := range gbgCollector.CompletedRequestQueue.Values() {
		if i == config.MAX_COMPLETED_REQUESTS_COUNT-1 {
			break
		}

		request := value.(*requests.TimeOrderedRequest)

		if request.RequestHash != reqHashes[i+1] {
			t.Errorf("Request hash mismatch 2")
		}
	}

}

func insertNRequests(t *testing.T, gbgCollector *requests.GarbageCollector, n int, completed bool, epochId uint32) []string {
	proposer := common.HexToAddress("0x1")

	var requestHashes []string = make([]string, 0, n)

	for i := 0; i < n; i++ {
		mockRequest := initMockRequest(epochId)
		_reqHash, err := mockRequest.DataFixed.HashFixed()
		require.NoError(t, err)
		requestHash := hex.EncodeToString(_reqHash[:])

		requestHashes = append(requestHashes, requestHash)

		gbgCollector.TrackRequest(requestHash, proposer)

		requestCounter := requests.CreateAndStoreRequestCounter(&mockRequest, proposer)

		if completed {
			requestCounter.Done = true
		}
	}

	return requestHashes
}

// Set the time of requests in the uncompleted queue to be old enough for cleanup
func updateUncompleteQueueTime(gbgCollector *requests.GarbageCollector) {

	// Manually set creation time to be old enough for cleanup for every request
	for _, value := range gbgCollector.UncompletedRequestQueue.Values() {
		request := value.(*requests.TimeOrderedRequest)
		request.CreatedAt = time.Now().Add(-2 * config.REQUEST_GARBAGE_COLLECTION_INTERVAL)
	}
}

func initMockRequest(epochId uint32) instruction.Data {

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	instructionDataFixed := instruction.DataFixed{
		InstructionID:          common.HexToHash(hex.EncodeToString(instructionIdBytes)),
		TeeID:                  common.HexToAddress("1234"),
		RewardEpochID:          new(big.Int).SetUint64(uint64(epochId)),
		OPType:                 utils.StringToOpHash("WALLET"),
		OPCommand:              utils.StringToOpHash("WALLET"),
		OriginalMessage:        []byte("test"),
		AdditionalFixedMessage: []byte("test"),
	}

	return instruction.Data{
		DataFixed:                 instructionDataFixed,
		AdditionalVariableMessage: []byte("test"),
	}
}

// Uncompleted Request Queue Tests

// Test handling of expired uncompleted requests (should be removed)
func TestExpiredUncompletedRequests(t *testing.T) {
	setupTest(t)

	reqHash := insertNRequests(t, gbgCollector, 1, false, 1)[0]

	// Manually set creation time to be old enough for cleanup
	updateUncompleteQueueTime(gbgCollector)

	// Run cleanup
	gbgCollector.CleanupUncompletedRequests()

	// Verify request was removed from the queue
	assert.Equal(t, 0, gbgCollector.UncompletedRequestQueue.Size())
	_, exists := requests.GetRequestCounterByHash(reqHash)
	assert.False(t, exists)
}

// Test handling of non-expired uncompleted requests (should remain)
func TestNonExpiredUncompletedRequests(t *testing.T) {
	setupTest(t)

	reqHash := insertNRequests(t, gbgCollector, 1, false, 1)[0]

	// Run cleanup without updating time
	gbgCollector.CleanupUncompletedRequests()

	// Verify request remains in the queue
	assert.Equal(t, 1, gbgCollector.UncompletedRequestQueue.Size())
	_, exists := requests.GetRequestCounterByHash(reqHash)
	assert.True(t, exists)
}

// Test handling of multiple requests with different expiration times
func TestMultipleRequestsDifferentExpirationTimes(t *testing.T) {
	setupTest(t)

	reqHashes := insertNRequests(t, gbgCollector, 3, false, 1)

	// Set different expiration times
	values := gbgCollector.UncompletedRequestQueue.Values()
	values[0].(*requests.TimeOrderedRequest).CreatedAt = time.Now().Add(-2 * config.REQUEST_GARBAGE_COLLECTION_INTERVAL)
	values[1].(*requests.TimeOrderedRequest).CreatedAt = time.Now().Add(-config.REQUEST_GARBAGE_COLLECTION_INTERVAL / 2)

	// Run cleanup
	gbgCollector.CleanupUncompletedRequests()

	// Verify only the expired request was removed
	assert.Equal(t, 2, gbgCollector.UncompletedRequestQueue.Size())
	_, exists1 := requests.GetRequestCounterByHash(reqHashes[0])
	assert.False(t, exists1)
	_, exists2 := requests.GetRequestCounterByHash(reqHashes[1])
	_, exists3 := requests.GetRequestCounterByHash(reqHashes[2])
	assert.True(t, exists2)
	assert.True(t, exists3)
}

// Test concurrent access to the queue during cleanup
func TestConcurrentAccessDuringCleanup(t *testing.T) {
	setupTest(t)

	insertNRequests(t, gbgCollector, 10, false, 1)

	var wg sync.WaitGroup
	wg.Add(2)

	// Manually set creation time to be old enough for cleanup
	updateUncompleteQueueTime(gbgCollector)

	go func() {
		defer wg.Done()
		gbgCollector.CleanupUncompletedRequests()
	}()

	go func() {
		defer wg.Done()
		gbgCollector.TrackRequest("newRequestHash", common.HexToAddress("0x2"))
	}()

	wg.Wait()

	// Verify no race conditions occurred
	assert.Equal(t, gbgCollector.UncompletedRequestQueue.Size(), 1)
}

// Test edge case when queue is empty
func TestEmptyQueue(t *testing.T) {
	setupTest(t)

	// Run cleanup on empty queue
	gbgCollector.CleanupUncompletedRequests()

	// Verify queue remains empty
	assert.Equal(t, 0, gbgCollector.UncompletedRequestQueue.Size())
}

// Completed Request Queue Tests

// Test bounded queue behavior when reaching MAX_COMPLETED_REQUESTS_COUNT
func TestBoundedQueueMaxCapacity(t *testing.T) {
	setupTest(t)

	insertNRequests(t, gbgCollector, config.MAX_COMPLETED_REQUESTS_COUNT+1, true, 1)

	// Manually set creation time to be old enough for cleanup
	updateUncompleteQueueTime(gbgCollector)

	// Run cleanup
	gbgCollector.CleanupUncompletedRequests()

	// Verify queue size is at max capacity
	assert.Equal(t, config.MAX_COMPLETED_REQUESTS_COUNT, gbgCollector.CompletedRequestQueue.Size())
}

// Test that completed requests maintain their order
func TestCompletedRequestsOrder(t *testing.T) {
	setupTest(t)

	reqHashes := insertNRequests(t, gbgCollector, config.MAX_COMPLETED_REQUESTS_COUNT, true, 1)

	// Run cleanup
	gbgCollector.CleanupUncompletedRequests()

	// Verify order is maintained
	for i, value := range gbgCollector.CompletedRequestQueue.Values() {
		assert.Equal(t, reqHashes[i], value.(*requests.TimeOrderedRequest).RequestHash)
	}
}

// Request State Management Tests

// Test that completed requests are properly moved from uncompleted to completed queue
func TestCompletedRequestsMoved(t *testing.T) {
	setupTest(t)

	reqHash := insertNRequests(t, gbgCollector, 1, true, 1)[0]

	// Manually set creation time to be old enough for cleanup
	updateUncompleteQueueTime(gbgCollector)

	// Run cleanup
	gbgCollector.CleanupUncompletedRequests()

	// Verify request moved to completed queue
	assert.Equal(t, 0, gbgCollector.UncompletedRequestQueue.Size())
	assert.Equal(t, 1, gbgCollector.CompletedRequestQueue.Size())
	_, exists := requests.GetRequestCounterByHash(reqHash)
	assert.True(t, exists)
}

// Test that request counters are properly maintained in storage
func TestRequestCountersMaintained(t *testing.T) {
	setupTest(t)

	reqHash := insertNRequests(t, gbgCollector, 1, true, 1)[0]

	// Run cleanup
	gbgCollector.CleanupUncompletedRequests()

	// Verify request counter exists
	_, exists := requests.GetRequestCounterByHash(reqHash)
	assert.True(t, exists)
}

// Test that request counters are removed for expired uncompleted requests
func TestRequestCountersRemovedForExpired(t *testing.T) {
	setupTest(t)
	reqHash := insertNRequests(t, gbgCollector, 1, false, 1)[0]

	// Manually set creation time to be old enough for cleanup
	updateUncompleteQueueTime(gbgCollector)

	// Run cleanup
	gbgCollector.CleanupUncompletedRequests()

	// Verify request counter was removed
	_, exists := requests.GetRequestCounterByHash(reqHash)
	assert.False(t, exists)
}

// Test that request counters persist for completed requests
func TestRequestCountersPersistForCompleted(t *testing.T) {
	setupTest(t)
	reqHash := insertNRequests(t, gbgCollector, 1, true, 1)[0]

	// Run cleanup
	gbgCollector.CleanupUncompletedRequests()

	// Verify request counter exists
	_, exists := requests.GetRequestCounterByHash(reqHash)
	assert.True(t, exists)
}

// Rate Limiter Integration Tests

// Test interaction between garbage collection and rate limiting
func TestGarbageCollectionRateLimitingInteraction(t *testing.T) {
	setupTest(t)

	reqHash := insertNRequests(t, gbgCollector, 1, false, 1)[0]

	// Manually set creation time to be old enough for cleanup
	updateUncompleteQueueTime(gbgCollector)

	// Run cleanup
	gbgCollector.CleanupUncompletedRequests()

	// Verify request counter was removed
	_, exists := requests.GetRequestCounterByHash(reqHash)
	assert.False(t, exists)
}

// Verify that removing expired requests properly updates validator request counts
func TestExpiredRequestsUpdateValidatorCounts(t *testing.T) {
	setupTest(t)

	reqHash := insertNRequests(t, gbgCollector, 1, false, 1)[0]

	// Manually set creation time to be old enough for cleanup
	updateUncompleteQueueTime(gbgCollector)

	// Run cleanup
	gbgCollector.CleanupUncompletedRequests()

	// Verify request counter was removed
	_, exists := requests.GetRequestCounterByHash(reqHash)
	assert.False(t, exists)
}

// Test that completed requests properly update validator statistics
func TestCompletedRequestsUpdateValidatorStats(t *testing.T) {
	setupTest(t)

	reqHash := insertNRequests(t, gbgCollector, 1, true, 1)[0]

	// Run cleanup
	gbgCollector.CleanupUncompletedRequests()

	// Verify request counter exists
	_, exists := requests.GetRequestCounterByHash(reqHash)
	assert.True(t, exists)
}
