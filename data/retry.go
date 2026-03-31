package data

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
)

const (
	maxRetries    = 3
	baseBackoff   = 2 * time.Second
	backoffFactor = 2
)

// isTransientError returns true for errors that indicate a temporary GitHub API failure.
func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, indicator := range []string{" 502 ", " 503 ", " 429 "} {
		if strings.Contains(msg, indicator) {
			return true
		}
	}
	return false
}

// withRetry executes fn up to maxRetries times with exponential backoff
// when the error is transient. Non-transient errors are returned immediately.
func withRetry(logger hclog.Logger, operation string, fn func() error) error {
	var err error
	backoff := baseBackoff

	for attempt := 1; attempt <= maxRetries; attempt++ {
		logger.Trace(fmt.Sprintf("attempting '%s' (%d/%d)", operation, attempt, maxRetries))
		err = fn()
		if err == nil {
			return nil
		}
		if !isTransientError(err) {
			return err
		}
		if attempt < maxRetries {
			logger.Warn(fmt.Sprintf("%s failed (attempt %d/%d), retrying in %s: %s", operation, attempt, maxRetries, backoff, err))
			time.Sleep(backoff)
			backoff *= backoffFactor
		}
	}
	return fmt.Errorf("%s failed after %d attempts: %w", operation, maxRetries, err)
}
