package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestConfigureLogger(t *testing.T) {
	// Test that configureLogger doesn't panic and handles different levels
	tests := []struct {
		name  string
		level string
	}{
		{"Debug level", "debug"},
		{"Info level", "info"},
		{"Warn level", "warn"},
		{"Error level", "error"},
		{"Invalid level", "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This test just ensures configureLogger runs without panicking
			// and properly handles different log levels
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("configureLogger panicked with %v", r)
				}
			}()

			// Configure logger with test level
			configureLogger(tt.level)

			// The actual logging behavior is tested by the fact that
			// the function runs without panicking
		})
	}
}

func TestReadTokensFromFile(t *testing.T) {
	// Create a temporary file with test tokens
	content := `# This is a comment
token1
token2

# Another comment
token3
`

	tmpFile, err := os.CreateTemp("", "tokens-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write content to temp file
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Test reading tokens
	tokens, err := readTokensFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read tokens: %v", err)
	}

	expectedTokens := []string{"token1", "token2", "token3"}
	if len(tokens) != len(expectedTokens) {
		t.Errorf("Expected %d tokens, got %d", len(expectedTokens), len(tokens))
	}

	for i, expected := range expectedTokens {
		if tokens[i] != expected {
			t.Errorf("Expected token %d to be %s, got %s", i, expected, tokens[i])
		}
	}
}

func TestReadTokensFromFile_NotFound(t *testing.T) {
	_, err := readTokensFromFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestReadTokensFromFile_EmptyFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "empty-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	tokens, err := readTokensFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read empty file: %v", err)
	}

	if len(tokens) != 0 {
		t.Errorf("Expected no tokens from empty file, got %d", len(tokens))
	}
}

func TestXForwardedHeaders_ExistingHeaders(t *testing.T) {
	mockServer := createMockTargetServer()
	defer mockServer.Close()

	client := &http.Client{}
	handler := createProxyHandler(client, []string{"token"}, "", true, 10, true)

	// Parse mock server URL
	serverURL, err := url.Parse(mockServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse mock server URL: %v", err)
	}

	// Extract host and port separately
	host := serverURL.Hostname()
	port := serverURL.Port()
	if port == "" {
		port = "80"
	}
	path := fmt.Sprintf("/token/http/%s/%s/test", host, port)

	req := httptest.NewRequest("GET", "http://example.com"+path, nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Host = "proxy.example.com"
	// Set existing X-Forwarded-For header
	req.Header.Set("X-Forwarded-For", "10.0.0.1")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	bodyStr := string(body)
	// Check that both IPs are present
	if !strings.Contains(bodyStr, "Header X-Forwarded-For: 10.0.0.1, 192.168.1.100") {
		t.Error("Expected X-Forwarded-For to append new IP")
	}
}

func TestXForwardedHeaders_HTTPS(t *testing.T) {
	mockServer := createMockTargetServer()
	defer mockServer.Close()

	client := &http.Client{}
	handler := createProxyHandler(client, []string{"token"}, "", true, 10, true)

	// Parse mock server URL
	serverURL, err := url.Parse(mockServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse mock server URL: %v", err)
	}

	// Extract host and port separately
	host := serverURL.Hostname()
	port := serverURL.Port()
	if port == "" {
		port = "80"
	}
	path := fmt.Sprintf("/token/http/%s/%s/test", host, port)

	req := httptest.NewRequest("GET", "https://example.com"+path, nil)
	req.TLS = &tls.ConnectionState{} // Simulate HTTPS

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "Header X-Forwarded-Proto: https") {
		t.Error("Expected X-Forwarded-Proto: https for HTTPS request")
	}
}

func TestRequestWithSpecialHeaders(t *testing.T) {
	mockServer := createMockTargetServer()
	defer mockServer.Close()

	client := &http.Client{}
	handler := createProxyHandler(client, []string{"token"}, "", true, 10, true)

	// Parse mock server URL
	serverURL, err := url.Parse(mockServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse mock server URL: %v", err)
	}

	// Extract host and port separately
	host := serverURL.Hostname()
	port := serverURL.Port()
	if port == "" {
		port = "80"
	}
	path := fmt.Sprintf("/token/http/%s/%s/test", host, port)

	req := httptest.NewRequest("GET", "http://example.com"+path, nil)
	// Add headers that might need special handling
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("Expect", "100-continue")
	req.Header.Set("Upgrade", "websocket")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestRequestBodyHandling(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"received": "%s", "length": %d}`, string(body), len(body))
	}))
	defer mockServer.Close()

	client := &http.Client{}
	handler := createProxyHandler(client, []string{"token"}, "", true, 10, true)

	// Parse mock server URL
	serverURL, err := url.Parse(mockServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse mock server URL: %v", err)
	}

	// Extract host and port separately
	host := serverURL.Hostname()
	port := serverURL.Port()
	if port == "" {
		port = "80"
	}
	path := fmt.Sprintf("/token/http/%s/%s/test", host, port)

	// Test with empty body
	t.Run("Empty body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "http://example.com"+path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		if !strings.Contains(string(body), `"length": 0`) {
			t.Error("Expected body length to be 0")
		}
	})

	// Test with large body
	t.Run("Large body", func(t *testing.T) {
		largeBody := strings.Repeat("x", 10000)
		req := httptest.NewRequest("POST", "http://example.com"+path, strings.NewReader(largeBody))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		if !strings.Contains(string(body), `"length": 10000`) {
			t.Error("Expected body length to be 10000")
		}
	})
}

func TestConfigureLogger_NonTerminal(t *testing.T) {
	// Save original stderr
	origStderr := os.Stderr

	// Create a pipe to redirect stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}

	// Redirect stderr to the pipe
	os.Stderr = w
	defer func() {
		os.Stderr = origStderr
		r.Close()
		w.Close()
	}()

	// Configure logger - this should use the non-terminal branch
	configureLogger("info")

	// Restore stderr to ensure the logger writes to the pipe
	w.Close()

	// Read from the pipe to verify it works
	buf := make([]byte, 1024)
	n, err := r.Read(buf)
	if err != nil && err.Error() != "EOF" {
		t.Fatalf("Failed to read from pipe: %v", err)
	}

	// We don't need to check the content, just that it didn't panic
	// and wrote something to the non-terminal output
	_ = n
}
