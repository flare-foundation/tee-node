package wallets

import (
	"sync"
	"tee-node/pkg/config"
	"time"

	"github.com/emirpasic/gods/queues/arrayqueue"
)

// Todo: Currently this is a stripped down copy of requests garbage collection. Since the latter is going
// to be moved to proxy, we can not join them into one.
var PendingWalletGarbageCollector *GarbageCollector

func init() {
	PendingWalletGarbageCollector = NewGarbageCollector()
	PendingWalletGarbageCollector.Start()
}

// GarbageCollector handles periodic cleanup of completed/expired requests
type GarbageCollector struct {
	UncompletedRequestQueue *arrayqueue.Queue // Time-ordered request queue for uncompleted requests

	queueMutex sync.Mutex
}

// TimeOrderedRequest tracks a request with its creation time
type TimeOrderedPendingWalletBackup struct {
	BackupId  WalletBackupId // Id of the
	CreatedAt time.Time      // When the request was created
	Index     int            // Index in the heap (used by container/heap)
}

func NewGarbageCollector() *GarbageCollector {
	// Create array queues for uncompleted and completed requests
	uncompletedQueue := arrayqueue.New()

	return &GarbageCollector{
		UncompletedRequestQueue: uncompletedQueue,
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
func (m *GarbageCollector) TrackRequest(backupId WalletBackupId) {
	m.queueMutex.Lock()
	defer m.queueMutex.Unlock()

	timedRequest := &TimeOrderedPendingWalletBackup{
		BackupId:  backupId,
		CreatedAt: time.Now(),
	}

	m.UncompletedRequestQueue.Enqueue(timedRequest)
}

// CleanupUncompletedRequests removes uncompleted requests older than the expiration time from the uncompleted requests queue
// Adds the completed requests to the completed requests queue
func (m *GarbageCollector) CleanupUncompletedRequests() {
	m.queueMutex.Lock()
	defer m.queueMutex.Unlock()

	cutoffTime := time.Now().Add(-config.PENDING_BACKUP_GARBAGE_COLLECTION_INTERVAL)

	// Process requests until we hit one that's not expired yet
	for !m.UncompletedRequestQueue.Empty() {
		// Peek at the oldest request
		value, ok := m.UncompletedRequestQueue.Peek()
		// this should not be possible
		if !ok {
			break
		}
		oldest := value.(*TimeOrderedPendingWalletBackup)

		// If it's not old enough to expire, we're done
		if oldest.CreatedAt.After(cutoffTime) {
			break
		}

		// Dequeue it from the queue
		m.UncompletedRequestQueue.Dequeue()

		// Remove it from the storage
		RemovePendingBackup(oldest.BackupId)
	}
}

func DestroyGarbageCollector() {
	PendingWalletGarbageCollector.UncompletedRequestQueue.Clear()
}
