package session

// MetricsCallback provides hooks for reporting metrics
// All methods should be safe to call even if the callback is nil
type MetricsCallback interface {
	// Session pool metrics
	SessionPoolUpdate(idle, active, total int)
	SessionCreated(reason string)
	SessionClosed(reason string, ageSeconds float64)
	SessionOldest(ageSeconds float64)

	// Ensure idle session metrics
	EnsureIdleDeficit(deficit int)
	EnsureIdleCreatedCycle(count int)

	// Stream metrics
	StreamOpened()
	StreamClosed()
	StreamError()
}
