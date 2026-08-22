package audit

import (
	"log/slog"
	"sync"
)

// AuditLog represents a single authorization decision to be recorded.
type AuditLog struct {
	PrincipalID string
	Action      string
	ResourceID  string
	Allowed     bool
	Reason      string
	PolicyId    string
	LatencyNs   int64
}

// AuditLogger manages the asynchronous flushing of audit logs.
type AuditLogger struct {
	logChan chan AuditLog
	wg      sync.WaitGroup
}

// NewAuditLogger initializes the AuditLogger with a bounded channel size (e.g., 10000).
func NewAuditLogger(bufferSize int) *AuditLogger {
	return &AuditLogger{
		logChan: make(chan AuditLog, bufferSize),
	}
}

// Start spins up background goroutines to process logs off the main request path.
func (l *AuditLogger) Start(workers int) {
	for i := 0; i < workers; i++ {
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			// Automatically stops when logChan is closed
			for record := range l.logChan {
				slog.Info("authorization_decision",
					slog.String("principal", record.PrincipalID),
					slog.String("action", record.Action),
					slog.String("resource", record.ResourceID),
					slog.Bool("allowed", record.Allowed),
					slog.String("reason", record.Reason),
					slog.String("policy_id", record.PolicyId),
					slog.Int64("latency_ns", record.LatencyNs),
				)
			}
		}()
	}
}

// LogDecision pushes the record to the channel without blocking.
func (l *AuditLogger) LogDecision(record AuditLog) {
	select {
	case l.logChan <- record:
		// Successfully queued!
	default:
		// Drop-and-count strategy if the buffer overflows to protect engine latency.
		slog.Warn("audit log buffer full, dropping record")
	}
}

// Stop gracefully closes the channel and waits for workers to finish draining logs.
func (l *AuditLogger) Stop() {
	close(l.logChan)
	l.wg.Wait()
}
