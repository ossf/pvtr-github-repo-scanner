package data

import (
	"errors"
	"testing"

	"github.com/hashicorp/go-hclog"
)

func TestIsTransientError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"502 bad gateway", errors.New("non-200 OK status code: 502 Bad Gateway"), true},
		{"503 service unavailable", errors.New("unexpected response: 503 Service Unavailable"), true},
		{"429 rate limit", errors.New("unexpected response: 429 Too Many Requests"), true},
		{"404 not found", errors.New("unexpected response: 404 Not Found"), false},
		{"auth error", errors.New("401 Unauthorized"), false},
		{"network error", errors.New("connection refused"), false},
		{"false positive url with 502", errors.New("GET https://api.example.com/v502/resource failed"), false},
		{"false positive number with 429", errors.New("processed 4291 records"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTransientError(tt.err); got != tt.expected {
				t.Errorf("isTransientError(%v) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

func TestWithRetry_SucceedsOnFirstAttempt(t *testing.T) {
	logger := hclog.NewNullLogger()
	calls := 0

	err := withRetry(logger, "test op", func() error {
		calls++
		return nil
	})

	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestWithRetry_RetriesOnTransientError(t *testing.T) {
	logger := hclog.NewNullLogger()
	calls := 0

	err := withRetry(logger, "test op", func() error {
		calls++
		if calls < 3 {
			return errors.New("non-200 OK status code: 502 Bad Gateway")
		}
		return nil
	})

	if err != nil {
		t.Errorf("expected no error after retry, got: %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
}

func TestWithRetry_DoesNotRetryNonTransientError(t *testing.T) {
	logger := hclog.NewNullLogger()
	calls := 0

	err := withRetry(logger, "test op", func() error {
		calls++
		return errors.New("404 Not Found")
	})

	if err == nil {
		t.Error("expected error, got nil")
	}
	if calls != 1 {
		t.Errorf("expected 1 call for non-transient error, got %d", calls)
	}
}

func TestWithRetry_ExhaustsRetries(t *testing.T) {
	logger := hclog.NewNullLogger()
	calls := 0
	sentinel := errors.New("non-200 OK status code: 502 Bad Gateway")

	err := withRetry(logger, "test op", func() error {
		calls++
		return sentinel
	})

	if err == nil {
		t.Error("expected error after exhausting retries, got nil")
	}
	if calls != maxRetries {
		t.Errorf("expected %d calls, got %d", maxRetries, calls)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel error, got: %v", err)
	}
}
