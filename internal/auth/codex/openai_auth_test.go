package codex

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRefreshTokensWithRetry_NonRetryableOnlyAttemptsOnce(t *testing.T) {
	var calls int32
	auth := &CodexAuth{
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				atomic.AddInt32(&calls, 1)
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(strings.NewReader(`{"error":"invalid_grant","code":"refresh_token_reused"}`)),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			}),
		},
	}

	_, err := auth.RefreshTokensWithRetry(context.Background(), "dummy_refresh_token", 3)
	if err == nil {
		t.Fatalf("expected error for non-retryable refresh failure")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "refresh_token_reused") {
		t.Fatalf("expected refresh_token_reused in error, got: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 refresh attempt, got %d", got)
	}
}

func TestRefreshFromSessionToken_ParsesSessionPayload(t *testing.T) {
	auth := &CodexAuth{
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet {
					t.Fatalf("expected GET request, got %s", req.Method)
				}
				if req.URL.String() != ChatGPTSessionURL {
					t.Fatalf("expected %s, got %s", ChatGPTSessionURL, req.URL.String())
				}
				if got := req.Header.Get("Cookie"); !strings.Contains(got, "__Secure-next-auth.session-token=test_session") {
					t.Fatalf("expected session cookie, got %q", got)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"accessToken":"eyJhbGciOiJub25lIn0.eyJlbWFpbCI6InNlc3Npb25AZXhhbXBsZS5jb20iLCJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdF8xMjMifX0.",
						"sessionToken":"rotated_session",
						"expires":"2026-06-27T17:03:48.205Z",
						"user":{"email":"session@example.com"},
						"account":{"id":"acct_123"}
					}`)),
					Header:  make(http.Header),
					Request: req,
				}, nil
			}),
		},
	}

	td, err := auth.RefreshFromSessionToken(context.Background(), "test_session")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if td.AccessToken == "" {
		t.Fatalf("expected access token")
	}
	if td.SessionToken != "rotated_session" {
		t.Fatalf("expected rotated session token, got %q", td.SessionToken)
	}
	if td.AccountID != "acct_123" {
		t.Fatalf("expected account id acct_123, got %q", td.AccountID)
	}
	if td.Email != "session@example.com" {
		t.Fatalf("expected email session@example.com, got %q", td.Email)
	}
	if td.Expire != "2026-06-27T17:03:48.205Z" {
		t.Fatalf("expected expiry from session payload, got %q", td.Expire)
	}
}
