package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestUploadAuthFile_BatchMultipart(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	files := []struct {
		name    string
		content string
	}{
		{name: "alpha.json", content: `{"type":"codex","email":"alpha@example.com"}`},
		{name: "beta.json", content: `{"type":"claude","email":"beta@example.com"}`},
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, file := range files {
		part, err := writer.CreateFormFile("file", file.name)
		if err != nil {
			t.Fatalf("failed to create multipart file: %v", err)
		}
		if _, err = part.Write([]byte(file.content)); err != nil {
			t.Fatalf("failed to write multipart content: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close multipart writer: %v", err)
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "/v0/management/auth-files", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	ctx.Request = req

	h.UploadAuthFile(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected upload status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if got, ok := payload["uploaded"].(float64); !ok || int(got) != len(files) {
		t.Fatalf("expected uploaded=%d, got %#v", len(files), payload["uploaded"])
	}

	for _, file := range files {
		fullPath := filepath.Join(authDir, file.name)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			t.Fatalf("expected uploaded file %s to exist: %v", file.name, err)
		}
		if string(data) != file.content {
			t.Fatalf("expected file %s content %q, got %q", file.name, file.content, string(data))
		}
	}

	auths := manager.List()
	if len(auths) != len(files) {
		t.Fatalf("expected %d auth entries, got %d", len(files), len(auths))
	}
}

func TestUploadAuthFile_BatchMultipart_InvalidJSONDoesNotOverwriteExistingFile(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	existingName := "alpha.json"
	existingContent := `{"type":"codex","email":"alpha@example.com"}`
	if err := os.WriteFile(filepath.Join(authDir, existingName), []byte(existingContent), 0o600); err != nil {
		t.Fatalf("failed to seed existing auth file: %v", err)
	}

	files := []struct {
		name    string
		content string
	}{
		{name: existingName, content: `{"type":"codex"`},
		{name: "beta.json", content: `{"type":"claude","email":"beta@example.com"}`},
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, file := range files {
		part, err := writer.CreateFormFile("file", file.name)
		if err != nil {
			t.Fatalf("failed to create multipart file: %v", err)
		}
		if _, err = part.Write([]byte(file.content)); err != nil {
			t.Fatalf("failed to write multipart content: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close multipart writer: %v", err)
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "/v0/management/auth-files", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	ctx.Request = req

	h.UploadAuthFile(ctx)

	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("expected upload status %d, got %d with body %s", http.StatusMultiStatus, rec.Code, rec.Body.String())
	}

	data, err := os.ReadFile(filepath.Join(authDir, existingName))
	if err != nil {
		t.Fatalf("expected existing auth file to remain readable: %v", err)
	}
	if string(data) != existingContent {
		t.Fatalf("expected existing auth file to remain %q, got %q", existingContent, string(data))
	}

	betaData, err := os.ReadFile(filepath.Join(authDir, "beta.json"))
	if err != nil {
		t.Fatalf("expected valid auth file to be created: %v", err)
	}
	if string(betaData) != files[1].content {
		t.Fatalf("expected beta auth file content %q, got %q", files[1].content, string(betaData))
	}
}

func TestDeleteAuthFile_BatchQuery(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	files := []string{"alpha.json", "beta.json"}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(authDir, name), []byte(`{"type":"codex"}`), 0o600); err != nil {
			t.Fatalf("failed to write auth file %s: %v", name, err)
		}
	}

	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	h.tokenStore = &memoryAuthStore{}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(
		http.MethodDelete,
		"/v0/management/auth-files?name="+url.QueryEscape(files[0])+"&name="+url.QueryEscape(files[1]),
		nil,
	)
	ctx.Request = req

	h.DeleteAuthFile(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected delete status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if got, ok := payload["deleted"].(float64); !ok || int(got) != len(files) {
		t.Fatalf("expected deleted=%d, got %#v", len(files), payload["deleted"])
	}

	for _, name := range files {
		if _, err := os.Stat(filepath.Join(authDir, name)); !os.IsNotExist(err) {
			t.Fatalf("expected auth file %s to be removed, stat err: %v", name, err)
		}
	}
}

func TestListAuthFiles_ExposesCodexRefreshTokenMissingFlag(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	store := &memoryAuthStore{}
	manager := coreauth.NewManager(store, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	missingPath := filepath.Join(authDir, "missing.json")
	okPath := filepath.Join(authDir, "ok.json")
	for _, item := range []struct {
		path string
		data string
	}{
		{missingPath, `{"type":"codex","session_token":"session-only"}`},
		{okPath, `{"type":"codex","session_token":"session","refresh_token":"refresh"}`},
	} {
		if err := os.WriteFile(item.path, []byte(item.data), 0o600); err != nil {
			t.Fatalf("write auth file: %v", err)
		}
		if err := h.registerAuthFromFile(context.Background(), item.path, []byte(item.data)); err != nil {
			t.Fatalf("register auth from file: %v", err)
		}
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)

	h.ListAuthFiles(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected list status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var payload struct {
		Files []map[string]any `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	flags := map[string]bool{}
	for _, file := range payload.Files {
		name, _ := file["name"].(string)
		flag, _ := file["codex_refresh_token_missing"].(bool)
		flags[name] = flag
	}
	if !flags["missing.json"] {
		t.Fatalf("expected missing.json to be flagged")
	}
	if flags["ok.json"] {
		t.Fatalf("expected ok.json not to be flagged")
	}
}

func TestSupplementCodexRefreshTokens_RefreshesEligibleAuths(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	store := &memoryAuthStore{}
	manager := coreauth.NewManager(store, nil, nil)
	refreshCalls := 0
	manager.RegisterExecutor(&stubProviderExecutor{refresh: func(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
		refreshCalls++
		cloned := auth.Clone()
		if cloned.Metadata == nil {
			cloned.Metadata = map[string]any{}
		}
		cloned.Metadata["access_token"] = "fresh-access"
		cloned.Metadata["refresh_token"] = "fresh-refresh"
		return cloned, nil
	}})
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	items := []struct {
		path string
		data string
	}{
		{filepath.Join(authDir, "eligible.json"), `{"type":"codex","session_token":"session-only"}`},
		{filepath.Join(authDir, "already.json"), `{"type":"codex","session_token":"session","refresh_token":"existing"}`},
		{filepath.Join(authDir, "other.json"), `{"type":"claude","session_token":"session-only"}`},
	}
	for _, item := range items {
		if err := os.WriteFile(item.path, []byte(item.data), 0o600); err != nil {
			t.Fatalf("write auth file: %v", err)
		}
		if err := h.registerAuthFromFile(context.Background(), item.path, []byte(item.data)); err != nil {
			t.Fatalf("register auth from file: %v", err)
		}
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/auth-files/codex-refresh-token/supplement", bytes.NewBufferString(`{"only_missing":true}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	h.SupplementCodexRefreshTokens(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected supplement status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	if refreshCalls != 1 {
		t.Fatalf("expected 1 refresh call, got %d", refreshCalls)
	}

	var payload struct {
		Status  string         `json:"status"`
		Summary map[string]any `json:"summary"`
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Status != "ok" {
		t.Fatalf("status = %q, want ok", payload.Status)
	}
	if got := int(payload.Summary["succeeded"].(float64)); got != 1 {
		t.Fatalf("succeeded = %d, want 1", got)
	}
	stored := h.findAuthByIdentifier("eligible.json")
	if stored == nil {
		t.Fatal("expected eligible auth")
	}
	if got, _ := stored.Metadata["refresh_token"].(string); got != "fresh-refresh" {
		t.Fatalf("refresh_token = %q, want fresh-refresh", got)
	}
}

func TestSupplementCodexRefreshTokens_ReturnsPartialOnRefreshFailure(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	store := &memoryAuthStore{}
	manager := coreauth.NewManager(store, nil, nil)
	manager.RegisterExecutor(&stubProviderExecutor{refresh: func(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
		if auth != nil && auth.FileName == "bad.json" {
			return nil, errors.New("boom")
		}
		cloned := auth.Clone()
		if cloned.Metadata == nil {
			cloned.Metadata = map[string]any{}
		}
		cloned.Metadata["refresh_token"] = "fresh-refresh"
		return cloned, nil
	}})
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	for _, item := range []struct {
		path string
		data string
	}{
		{filepath.Join(authDir, "good.json"), `{"type":"codex","session_token":"session-1"}`},
		{filepath.Join(authDir, "bad.json"), `{"type":"codex","session_token":"session-2"}`},
	} {
		if err := os.WriteFile(item.path, []byte(item.data), 0o600); err != nil {
			t.Fatalf("write auth file: %v", err)
		}
		if err := h.registerAuthFromFile(context.Background(), item.path, []byte(item.data)); err != nil {
			t.Fatalf("register auth from file: %v", err)
		}
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/auth-files/codex-refresh-token/supplement", bytes.NewBufferString(`{"only_missing":true}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	h.SupplementCodexRefreshTokens(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected supplement status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	var payload struct {
		Status  string         `json:"status"`
		Summary map[string]any `json:"summary"`
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Status != "partial" {
		t.Fatalf("status = %q, want partial", payload.Status)
	}
	if got := int(payload.Summary["failed"].(float64)); got != 1 {
		t.Fatalf("failed = %d, want 1", got)
	}
}
