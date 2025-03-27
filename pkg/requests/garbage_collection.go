package requests

import (
	"sync"
	"tee-node/pkg/config"
	"time"

	"github.com/emirpasic/gods/queues/arrayqueue"

	"github.com/ethereum/go-ethereum/common"
)

var RequestGarbageCollector *GarbageCollector

func init() {
	RequestGarbageCollector = NewGarbageCollector()
	RequestGarbageCollector.Start()
}

// TODO: Check thread safety?
// GarbageCollector handles periodic cleanup of completed/expired requests
type GarbageCollector struct {
	UncompletedRequestQueue *arrayqueue.Queue // Time-ordered request queue for uncompleted requests (rapidly changing)
	CompletedRequestQueue   *BoundedQueue     // Time-ordered request queue for completed requests (slowly changing)

	queueMutex sync.Mutex
}

// TimeOrderedRequest tracks a request with its creation time
type TimeOrderedRequest struct {
	RequestHash     string         // Hash of the request
	ProposerAddress common.Address // ID of the validator who proposed this request
	CreatedAt       time.Time      // When the request was created
	Index           int            // Index in the heap (used by container/heap)
}

type BoundedQueue struct {
	queue   *arrayqueue.Queue
	maxSize int
}

func NewBoundedQueue(maxSize int) *BoundedQueue {
	return &BoundedQueue{
		queue:   arrayqueue.New(),
		maxSize: maxSize,
	}
}

// Enqueue adds a new element to the queue and removes the oldest element if the queue is full
func (q *BoundedQueue) Enqueue(value interface{}) {
	if q.queue.Size() >= q.maxSize {
		req, _ := q.queue.Dequeue()
		timedRequest := req.(*TimeOrderedRequest)

		// Remove the request from the request counter storage
		RemoveRequestCounterByHash(timedRequest.RequestHash)
	}

	q.queue.Enqueue(value)
}

func (q *BoundedQueue) Size() int {
	return q.queue.Size()
}

func (q *BoundedQueue) Values() []interface{} {
	return q.queue.Values()
}

func NewGarbageCollector() *GarbageCollector {
	// Create array queues for uncompleted and completed requests
	uncompletedQueue := arrayqueue.New()
	completedQueue := NewBoundedQueue(config.MAX_COMPLETED_REQUESTS_COUNT)

	return &GarbageCollector{
		UncompletedRequestQueue: uncompletedQueue,
		CompletedRequestQueue:   completedQueue,
	}
}

// Start begins the periodic cleanup process
func (m *GarbageCollector) Start() {
	garbageTicker := time.NewTicker(config.CHECK_GARBAGE_COLLECTION_INTERVAL)
	go func() {
		for range garbageTicker.C {
			m.CleanupUncompletedRequests()
		}
	}()
}

// TrackRequest adds a new request to the time-ordered queue
func (m *GarbageCollector) TrackRequest(reqHash string, proposerAddress common.Address) {
	m.queueMutex.Lock()
	defer m.queueMutex.Unlock()

	timedRequest := &TimeOrderedRequest{
		RequestHash:     reqHash,
		ProposerAddress: proposerAddress,
		CreatedAt:       time.Now(),
	}

	m.UncompletedRequestQueue.Enqueue(timedRequest)
}

// CleanupUncompletedRequests removes uncompleted requests older than the expiration time from the uncompleted requests queue
// Adds the completed requests to the completed requests queue
func (m *GarbageCollector) CleanupUncompletedRequests() {
	m.queueMutex.Lock()
	defer m.queueMutex.Unlock()

	cutoffTime := time.Now().Add(-config.REQUEST_GARBAGE_COLLECTION_INTERVAL)

	// Process requests until we hit one that's not expired yet
	for !m.UncompletedRequestQueue.Empty() {
		// Peek at the oldest request
		value, ok := m.UncompletedRequestQueue.Peek()
		// this should not be possible
		if !ok {
			break
		}
		oldest := value.(*TimeOrderedRequest)

		// If it's not old enough to expire, we're done
		if oldest.CreatedAt.After(cutoffTime) {
			break
		}

		// Dequeue it from the queue
		m.UncompletedRequestQueue.Dequeue()

		performGarbageCollection(m, oldest)
	}
}

func performGarbageCollection(m *GarbageCollector, timedRequest *TimeOrderedRequest) {
	requestCounter, exists := GetRequestCounterByHash(timedRequest.RequestHash)
	if !exists {
		return
	}

	if requestCounter.Done {
		// Add the completed request to the completed requests queue
		m.CompletedRequestQueue.Enqueue(timedRequest)
	} else {
		// Request timed out without completion, remove it and leave the rate limiter counter as is
		RemoveRequestCounterByHash(timedRequest.RequestHash)
	}
}

func DestroyGarbageCollector() {
	RequestGarbageCollector.CompletedRequestQueue.queue.Clear()
	RequestGarbageCollector.UncompletedRequestQueue.Clear()
}
