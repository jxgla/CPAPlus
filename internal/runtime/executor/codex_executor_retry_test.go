package executor

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestParseCodexRetryAfter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	t.Run("resets_in_seconds", func(t *testing.T) {
		body := []byte(`{"error":{"type":"usage_limit_reached","resets_in_seconds":123}}`)
		retryAfter := parseCodexRetryAfter(http.StatusTooManyRequests, body, now)
		if retryAfter == nil {
			t.Fatalf("expected retryAfter, got nil")
		}
		if *retryAfter != 123*time.Second {
			t.Fatalf("retryAfter = %v, want %v", *retryAfter, 123*time.Second)
		}
	})

	t.Run("prefers resets_at", func(t *testing.T) {
		resetAt := now.Add(5 * time.Minute).Unix()
		body := []byte(`{"error":{"type":"usage_limit_reached","resets_at":` + itoa(resetAt) + `,"resets_in_seconds":1}}`)
		retryAfter := parseCodexRetryAfter(http.StatusTooManyRequests, body, now)
		if retryAfter == nil {
			t.Fatalf("expected retryAfter, got nil")
		}
		if *retryAfter != 5*time.Minute {
			t.Fatalf("retryAfter = %v, want %v", *retryAfter, 5*time.Minute)
		}
	})

	t.Run("fallback when resets_at is past", func(t *testing.T) {
		resetAt := now.Add(-1 * time.Minute).Unix()
		body := []byte(`{"error":{"type":"usage_limit_reached","resets_at":` + itoa(resetAt) + `,"resets_in_seconds":77}}`)
		retryAfter := parseCodexRetryAfter(http.StatusTooManyRequests, body, now)
		if retryAfter == nil {
			t.Fatalf("expected retryAfter, got nil")
		}
		if *retryAfter != 77*time.Second {
			t.Fatalf("retryAfter = %v, want %v", *retryAfter, 77*time.Second)
		}
	})

	t.Run("non-429 status code", func(t *testing.T) {
		body := []byte(`{"error":{"type":"usage_limit_reached","resets_in_seconds":30}}`)
		if got := parseCodexRetryAfter(http.StatusBadRequest, body, now); got != nil {
			t.Fatalf("expected nil for non-429, got %v", *got)
		}
	})

	t.Run("non usage_limit_reached error type", func(t *testing.T) {
		body := []byte(`{"error":{"type":"server_error","resets_in_seconds":30}}`)
		if got := parseCodexRetryAfter(http.StatusTooManyRequests, body, now); got != nil {
			t.Fatalf("expected nil for non-usage_limit_reached, got %v", *got)
		}
	})
}

func TestRetryCodexUnauthorizedOnce_RetriesAfterRefresh(t *testing.T) {
	auth := &cliproxyauth.Auth{Metadata: map[string]any{"refresh_token": "refresh-token"}}
	unauthorizedErr := statusErr{code: http.StatusUnauthorized, msg: "unauthorized"}
	refreshCalls := 0
	retryCalls := 0

	err := retryCodexUnauthorizedOnce(context.Background(), auth, unauthorizedErr,
		func(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
			refreshCalls++
			cloned := auth.Clone()
			if cloned.Metadata == nil {
				cloned.Metadata = map[string]any{}
			}
			cloned.Metadata["access_token"] = "fresh-access"
			return cloned, nil
		},
		func(ctx context.Context, refreshedAuth *cliproxyauth.Auth) error {
			retryCalls++
			if !codexUnauthorizedRetried(ctx) {
				t.Fatalf("expected retry context to be marked retried")
			}
			if got, _ := refreshedAuth.Metadata["access_token"].(string); got != "fresh-access" {
				t.Fatalf("access_token = %q, want fresh-access", got)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("retryCodexUnauthorizedOnce returned error: %v", err)
	}
	if refreshCalls != 1 {
		t.Fatalf("refreshCalls = %d, want 1", refreshCalls)
	}
	if retryCalls != 1 {
		t.Fatalf("retryCalls = %d, want 1", retryCalls)
	}
}

func TestRetryCodexUnauthorizedOnce_SkipsWhenAlreadyRetried(t *testing.T) {
	auth := &cliproxyauth.Auth{Metadata: map[string]any{"session_token": "session-token"}}
	unauthorizedErr := statusErr{code: http.StatusUnauthorized, msg: "unauthorized"}
	refreshCalls := 0
	retryCalls := 0

	err := retryCodexUnauthorizedOnce(codexMarkUnauthorizedRetried(context.Background()), auth, unauthorizedErr,
		func(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
			refreshCalls++
			return auth, nil
		},
		func(ctx context.Context, refreshedAuth *cliproxyauth.Auth) error {
			retryCalls++
			return nil
		},
	)
	if !errors.Is(err, unauthorizedErr) {
		t.Fatalf("expected original unauthorized error, got %v", err)
	}
	if refreshCalls != 0 {
		t.Fatalf("refreshCalls = %d, want 0", refreshCalls)
	}
	if retryCalls != 0 {
		t.Fatalf("retryCalls = %d, want 0", retryCalls)
	}
}

func TestRetryCodexUnauthorizedOnce_SkipsWithoutRefreshableTokens(t *testing.T) {
	auth := &cliproxyauth.Auth{Metadata: map[string]any{"access_token": "access-only"}}
	unauthorizedErr := statusErr{code: http.StatusUnauthorized, msg: "unauthorized"}
	refreshCalls := 0
	retryCalls := 0

	err := retryCodexUnauthorizedOnce(context.Background(), auth, unauthorizedErr,
		func(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
			refreshCalls++
			return auth, nil
		},
		func(ctx context.Context, refreshedAuth *cliproxyauth.Auth) error {
			retryCalls++
			return nil
		},
	)
	if !errors.Is(err, unauthorizedErr) {
		t.Fatalf("expected original unauthorized error, got %v", err)
	}
	if refreshCalls != 0 {
		t.Fatalf("refreshCalls = %d, want 0", refreshCalls)
	}
	if retryCalls != 0 {
		t.Fatalf("retryCalls = %d, want 0", retryCalls)
	}
}

func TestRetryCodexUnauthorizedOnce_ReturnsOriginalErrorOnRefreshFailure(t *testing.T) {
	auth := &cliproxyauth.Auth{Metadata: map[string]any{"refresh_token": "refresh-token"}}
	unauthorizedErr := statusErr{code: http.StatusUnauthorized, msg: "unauthorized"}
	refreshCalls := 0
	retryCalls := 0

	err := retryCodexUnauthorizedOnce(context.Background(), auth, unauthorizedErr,
		func(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
			refreshCalls++
			return nil, errors.New("refresh failed")
		},
		func(ctx context.Context, refreshedAuth *cliproxyauth.Auth) error {
			retryCalls++
			return nil
		},
	)
	if !errors.Is(err, unauthorizedErr) {
		t.Fatalf("expected original unauthorized error, got %v", err)
	}
	if refreshCalls != 1 {
		t.Fatalf("refreshCalls = %d, want 1", refreshCalls)
	}
	if retryCalls != 0 {
		t.Fatalf("retryCalls = %d, want 0", retryCalls)
	}
}

func TestNewCodexStatusErrTreatsCapacityAsRetryableRateLimit(t *testing.T) {
	body := []byte(`{"error":{"message":"Selected model is at capacity. Please try a different model."}}`)

	err := newCodexStatusErr(http.StatusBadRequest, body)

	if got := err.StatusCode(); got != http.StatusTooManyRequests {
		t.Fatalf("status code = %d, want %d", got, http.StatusTooManyRequests)
	}
	if err.RetryAfter() != nil {
		t.Fatalf("expected nil explicit retryAfter for capacity fallback, got %v", *err.RetryAfter())
	}
}

func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}
