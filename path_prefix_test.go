package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestPathPrefix(t *testing.T) {
	mockServer := createMockTargetServer()
	defer mockServer.Close()

	// Test with tokens
	client := createTestHTTPClient()
	handlerWithTokens := createProxyHandler(client, []string{"token"}, "myprefix/v1", true, 10, true)

	// Test without tokens
	handlerWithoutTokens := createProxyHandler(client, []string{}, "myprefix/v1", true, 10, true)

	// Parse mock server URL
	serverURL, err := url.Parse(mockServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse mock server URL: %v", err)
	}

	// Extract host and port separately
	host := serverURL.Hostname()
	port := serverURL.Port()
	if port == "" {
		port = "80" // Default HTTP port
	}

	tests := []struct {
		name       string
		handler    http.Handler
		path       string
		wantStatus int
	}{
		{"Valid path prefix with token", handlerWithTokens, fmt.Sprintf("/myprefix/v1/token/http/%s/%s/test", host, port), http.StatusOK},
		{"Valid path prefix without token", handlerWithoutTokens, fmt.Sprintf("/myprefix/v1/http/%s/%s/test", host, port), http.StatusOK},
		{"Invalid path prefix", handlerWithTokens, fmt.Sprintf("/wrongprefix/token/http/%s/%s/test", host, port), http.StatusBadRequest},
		{"Missing path prefix", handlerWithTokens, fmt.Sprintf("/token/http/%s/%s/test", host, port), http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com"+tt.path, nil)
			w := httptest.NewRecorder()
			tt.handler.ServeHTTP(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}
		})
	}
}

func TestPathPrefix_Normalization(t *testing.T) {
	mockServer := createMockTargetServer()
	defer mockServer.Close()

	// Parse mock server URL
	serverURL, err := url.Parse(mockServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse mock server URL: %v", err)
	}

	// Extract host and port separately
	host := serverURL.Hostname()
	port := serverURL.Port()
	if port == "" {
		port = "80" // Default HTTP port
	}

	// Test with different prefix formats
	tests := []struct {
		name       string
		pathPrefix string
		wantStatus int
	}{
		{"Prefix without leading slash", "myprefix/v1", http.StatusOK},
		{"Prefix with leading slash", "/myprefix/v1", http.StatusOK},
		{"Prefix with trailing slash", "myprefix/v1/", http.StatusOK},
		{"Prefix with both slashes", "/myprefix/v1/", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := createTestHTTPClient()
			handler := createProxyHandler(client, []string{}, tt.pathPrefix, true, 10, true)

			requestPath := fmt.Sprintf("/myprefix/v1/http/%s/%s/test", host, port)
			req := httptest.NewRequest("GET", "http://example.com"+requestPath, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}
		})
	}
}
