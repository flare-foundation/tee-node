package requests_test

import (
	"math/big"
	"math/rand"
	"tee-node/pkg/config"
	"tee-node/pkg/requests"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimiterBasic(t *testing.T) {
	defer requests.DestroyState()

	validators := genRandomValidators(10)
	requests.UpdateRateLimiter(validators)

	validatorAddress := validators[0]

	// Test incrementing up to the limit
	for range config.MAX_PENDING_REQUESTS - 1 {
		err := requests.RateLimiterActive.IncrementRequestCount(validatorAddress)
		assert.NoError(t, err)
	}

	canPropose, err := requests.RateLimiterActive.CanProposeRequest(validatorAddress)
	require.NoError(t, err)
	assert.True(t, canPropose)

	// Test Reaching the limit
	err = requests.RateLimiterActive.IncrementRequestCount(validatorAddress)
	require.NoError(t, err)

	canPropose, err = requests.RateLimiterActive.CanProposeRequest(validatorAddress)
	require.NoError(t, err)
	assert.False(t, canPropose)

	// Test going over the limit
	err = requests.RateLimiterActive.IncrementRequestCount(validatorAddress)
	assert.Equal(t, "validator has too many pending requests", err.Error())

	// Test decrementing
	err = requests.RateLimiterActive.DecrementRequestCount(validatorAddress)
	assert.NoError(t, err)

	// Can propose again
	canPropose, err = requests.RateLimiterActive.CanProposeRequest(validatorAddress)
	require.NoError(t, err)
	assert.True(t, canPropose)

	// Should be able to increment again
	err = requests.RateLimiterActive.IncrementRequestCount(validatorAddress)
	assert.NoError(t, err)

	// Shouldn't be able to propose again
	canPropose, _ = requests.RateLimiterActive.CanProposeRequest(validatorAddress)
	assert.False(t, canPropose)
}

func TestClearPendingRequests(t *testing.T) {
	defer requests.DestroyState()

	validators := genRandomValidators(10)
	requests.UpdateRateLimiter(validators)

	// Create some pending requests for the first 10 validators
	for i := range 10 {
		validatorAddress := validators[i]
		for j := 0; j < config.MAX_PENDING_REQUESTS; j++ {
			err := requests.RateLimiterActive.IncrementRequestCount(validatorAddress)
			assert.NoError(t, err)
		}
	}

	// Clear pending requests
	requests.RateLimiterActive.ClearPendingRequests()

	// Check that all pending requests are cleared
	for i := range 10 {
		assert.Equal(t, requests.RateLimiterActive.Validators[validators[i].String()].PendingRequests, int(0))
	}

}

func TestValidatorRegistration(t *testing.T) {
	defer requests.DestroyState()

	validators := genRandomValidators(10)
	requests.UpdateRateLimiter(validators)

	// Verify all validators are registered in active policy
	for _, addr := range validators {
		validator, exists := requests.RateLimiterActive.Validators[addr.String()]
		require.True(t, exists, "Validator should be registered in active policy")

		// Verify fields are initialized to zero
		assert.Equal(t, addr, validator.Address, "Validator address should match")
		assert.Equal(t, 0, validator.PendingRequests, "PendingRequests should be initialized to 0")
		assert.Equal(t, 0, validator.TotalProposed, "TotalProposed should be initialized to 0")
		assert.Equal(t, 0, validator.TotalCompleted, "TotalCompleted should be initialized to 0")
	}

	// Create new validators for policy transition test
	newValidators := genRandomValidators(100)

	// Add some activity to active validators to see if it works
	for i := 0; i < 3; i++ {
		err := requests.RateLimiterActive.IncrementRequestCount(validators[0])
		require.NoError(t, err)
	}
	err := requests.RateLimiterActive.DecrementRequestCount(validators[0])
	require.NoError(t, err)

	// Test transition from active to past
	requests.UpdateRateLimiter(newValidators)

	// Verify old validators moved to past policy with their state intact
	for _, addr := range validators {
		validator, exists := requests.RateLimiterPast.Validators[addr.String()]
		require.True(t, exists, "Validator should be in past policy after transition")

		if addr == validators[0] {
			assert.Equal(t, 2, validator.PendingRequests, "PendingRequests should be preserved")
			assert.Equal(t, 3, validator.TotalProposed, "TotalProposed should be preserved")
			assert.Equal(t, 1, validator.TotalCompleted, "TotalCompleted should be preserved")
		} else {
			assert.Equal(t, 0, validator.PendingRequests, "PendingRequests should be initialized to 0")
		}
	}

	// Verify new validators are registered in active policy
	for _, addr := range newValidators {
		validator, exists := requests.RateLimiterActive.Validators[addr.String()]
		require.True(t, exists, "New validator should be registered in active policy")
		assert.Equal(t, 0, validator.PendingRequests, "PendingRequests should be initialized to 0")
	}

	// Verify old valdators can still propose
	for _, addr := range validators {
		err := requests.CanProposeNewRequest(addr, false)
		require.NoError(t, err)
	}

	// Update the rate limiter again to only include the new validators
	requests.UpdateRateLimiter(newValidators)

	// Verify old validators can't propose anymore
	for _, addr := range validators {
		err := requests.CanProposeNewRequest(addr, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "validator not registered")
	}

}

func TestRequestLimiting(t *testing.T) {
	defer requests.DestroyState()

	validators := genRandomValidators(10)
	requests.UpdateRateLimiter(validators)

	validatorAddress := validators[0]

	// Test incrementing until exactly the limit
	for i := 0; i < config.MAX_PENDING_REQUESTS; i++ {
		err := requests.RateLimiterActive.IncrementRequestCount(validatorAddress)
		require.NoError(t, err, "Should allow incrementing up to the limit")
	}

	// Verify CanProposeRequest returns false when at the limit
	canPropose, err := requests.RateLimiterActive.CanProposeRequest(validatorAddress)
	require.NoError(t, err)
	assert.False(t, canPropose, "Should not allow proposing when at limit")

	// Test IncrementRequestCount returns error when at limit
	err = requests.RateLimiterActive.IncrementRequestCount(validatorAddress)
	assert.Error(t, err, "Should return error when incrementing beyond limit")
	assert.Contains(t, err.Error(), "validator has too many pending requests")

	// Verify the pending count never exceeds the maximum
	validator := requests.RateLimiterActive.Validators[validatorAddress.String()]
	assert.Equal(t, config.MAX_PENDING_REQUESTS, validator.PendingRequests, "PendingRequests should not exceed maximum")

	// Decrement and verify we can increment again
	err = requests.RateLimiterActive.DecrementRequestCount(validatorAddress)
	require.NoError(t, err)

	assert.Equal(t, config.MAX_PENDING_REQUESTS-1, validator.PendingRequests, "PendingRequests should be decremented")

	// Should be able to increment again
	err = requests.RateLimiterActive.IncrementRequestCount(validatorAddress)
	assert.NoError(t, err, "Should allow incrementing after decrementing")

	// Verify back at the limit
	assert.Equal(t, config.MAX_PENDING_REQUESTS, validator.PendingRequests, "PendingRequests should be at maximum again")
}

func TestLimitHitCounter(t *testing.T) {
	defer requests.DestroyState()

	// Create enough validators to test the limit hit counter
	validators := genRandomValidators(config.LIMIT_HIT_COUNT + 5)
	requests.UpdateRateLimiter(validators)

	// Verify initial state
	assert.Equal(t, 0, requests.RateLimiterActive.LimitHitCounter,
		"Initial limit hit counter should be zero")

	// Fill up validators to their limits one by one and check counter increments
	for i := 0; i < config.LIMIT_HIT_COUNT-1; i++ {
		// Max out this validator's requests
		for j := 0; j < config.MAX_PENDING_REQUESTS; j++ {
			err := requests.RateLimiterActive.IncrementRequestCount(validators[i])
			require.NoError(t, err)
		}

		// Verify counter increased
		assert.Equal(t, i+1, requests.RateLimiterActive.LimitHitCounter,
			"Limit hit counter should increment when validator reaches max")

		// Verify system hasn't cleared requests yet
		for k := 0; k <= i; k++ {
			validator := requests.RateLimiterActive.Validators[validators[k].String()]
			assert.Equal(t, config.MAX_PENDING_REQUESTS, validator.PendingRequests,
				"Validator should still have max pending requests")
		}
	}

	// Verify we're one validator away from the threshold
	assert.Equal(t, config.LIMIT_HIT_COUNT-1, requests.RateLimiterActive.LimitHitCounter)

	// Max out one more validator to trigger the threshold
	for j := 0; j < config.MAX_PENDING_REQUESTS; j++ {
		err := requests.RateLimiterActive.IncrementRequestCount(validators[config.LIMIT_HIT_COUNT-1])
		require.NoError(t, err)
	}

	// Verify counter was reset after clearing
	assert.Equal(t, 0, requests.RateLimiterActive.LimitHitCounter,
		"Limit hit counter should reset after clearing pending requests")

	// Verify all pending requests were cleared
	for _, addr := range validators {
		validator := requests.RateLimiterActive.Validators[addr.String()]
		assert.Equal(t, 0, validator.PendingRequests,
			"All pending requests should be cleared when threshold is reached")
	}

	// Test system recovery - validators should be able to propose again
	for i := 0; i < 3; i++ {
		err := requests.RateLimiterActive.IncrementRequestCount(validators[i])
		require.NoError(t, err, "Validators should be able to propose after system recovery")
	}

	// Verify counter starts incrementing again from zero
	for j := 0; j < config.MAX_PENDING_REQUESTS; j++ {
		err := requests.RateLimiterActive.IncrementRequestCount(validators[config.LIMIT_HIT_COUNT])
		if j < config.MAX_PENDING_REQUESTS-1 {
			require.NoError(t, err)
		}
	}

	assert.Equal(t, 1, requests.RateLimiterActive.LimitHitCounter,
		"Limit hit counter should start incrementing from zero after reset")
}

func genRandomValidators(numValidators int) []common.Address {
	voters := make([]common.Address, 0)
	for range numValidators {
		validatorAddress := common.BigToAddress(big.NewInt(int64(rand.Intn(1000000))))
		voters = append(voters, validatorAddress)
	}

	return voters
}
