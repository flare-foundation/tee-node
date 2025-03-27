package utils

import "time"

// TimeProvider interface allows for mocking time
type TimeProvider interface {
	Now() time.Time
}

// RealTimeProvider uses the actual system clock
type RealTimeProvider struct{}

func (p RealTimeProvider) Now() time.Time {
	return time.Now()
}

var timeProvider TimeProvider = RealTimeProvider{}

// Refactor your original function to use the provider
func GetTimestampInMilliseconds() uint64 {
	return uint64(timeProvider.Now().UnixMilli())
}

func GetTimestampInSeconds() uint64 {
	return uint64(timeProvider.Now().Unix())
}

// TODO: This function is used for testing. Not sure if this is the best way to do this
func SetTimeProvider(provider TimeProvider) {
	timeProvider = provider
}
