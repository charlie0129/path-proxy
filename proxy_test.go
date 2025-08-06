package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// createTestHTTPClient creates a test HTTP client with connection pooling
func createTestHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
	}
}

// Test server that simulates a target server
func createMockTargetServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back request information
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Method: %s\n", r.Method)
		fmt.Fprintf(w, "Path: %s\n", r.URL.Path)
		fmt.Fprintf(w, "Host: %s\n", r.Host)
		fmt.Fprintf(w, "Query: %s\n", r.URL.RawQuery)

		// Echo back headers
		for name, values := range r.Header {
			for _, value := range values {
				fmt.Fprintf(w, "Header %s: %s\n", name, value)
			}
		}

		// Echo back body if present
		if r.Body != nil {
			body, err := io.ReadAll(r.Body)
			if err == nil && len(body) > 0 {
				fmt.Fprintf(w, "Body: %s\n", string(body))
			}
		}
	}))
}

// Test server that returns redirects
func createMockRedirectServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect1":
			http.Redirect(w, r, "/redirect2", http.StatusFound)
		case "/redirect2":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			fmt.Fprint(w, "Final destination after redirects")
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestTokenAuthentication(t *testing.T) {
	mockServer := createMockTargetServer()
	defer mockServer.Close()

	tokens := []string{"valid-token", "another-token"}
	client := createTestHTTPClient()
	handler := createProxyHandler(client, tokens, "", true, 10, true)

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
		path       string
		wantStatus int
	}{
		{"Valid token", fmt.Sprintf("/valid-token/http/%s/%s/test", host, port), http.StatusOK},
		{"Another valid token", fmt.Sprintf("/another-token/http/%s/%s/test", host, port), http.StatusOK},
		{"Invalid token", fmt.Sprintf("/invalid-token/http/%s/%s/test", host, port), http.StatusUnauthorized},
		{"Missing token", fmt.Sprintf("/http/%s/%s/test", host, port), http.StatusUnauthorized},
		{"Malformed token path", "/token/http", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com"+tt.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}
		})
	}
}

func TestNoTokenMode(t *testing.T) {
	mockServer := createMockTargetServer()
	defer mockServer.Close()

	client := createTestHTTPClient()
	handler := createProxyHandler(client, []string{}, "", true, 10, true)

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
		path       string
		wantStatus int
	}{
		{"Valid no token path", fmt.Sprintf("/http/%s/%s/test", host, port), http.StatusOK},
		{"Invalid path - missing protocol", "/example.com/test", http.StatusBadRequest},
		{"Invalid path - empty", "/", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com"+tt.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}
		})
	}
}

func TestURLParsing(t *testing.T) {
	mockServer := createMockTargetServer()
	defer mockServer.Close()

	client := createTestHTTPClient()
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
		port = "80" // Default HTTP port
	}

	tests := []struct {
		name      string
		path      string
		wantPath  string
		wantQuery string
	}{
		{
			"Simple path",
			fmt.Sprintf("/token/http/%s/%s/api/users", host, port),
			"/api/users",
			"",
		},
		{
			"Path with query",
			fmt.Sprintf("/token/http/%s/%s/search%%3Fq=test", host, port),
			"/search",
			"q=test",
		},
		{
			"Complex path",
			fmt.Sprintf("/token/http/%s/%s/v1/data/items/123%%3Ffilter=active", host, port),
			"/v1/data/items/123",
			"filter=active",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com"+tt.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			resp := w.Result()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200, got %d. Body: %s", resp.StatusCode, string(body))
			}

			bodyStr := string(body)
			if !strings.Contains(bodyStr, fmt.Sprintf("Path: %s", tt.wantPath)) {
				t.Errorf("Expected path to be %s, got: %s", tt.wantPath, bodyStr)
			}
			if tt.wantQuery != "" && !strings.Contains(bodyStr, fmt.Sprintf("Query: %s", tt.wantQuery)) {
				t.Errorf("Expected query to be %s, got: %s", tt.wantQuery, bodyStr)
			}
		})
	}
}

func TestRequestForwarding(t *testing.T) {
	mockServer := createMockTargetServer()
	defer mockServer.Close()

	client := createTestHTTPClient()
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
		port = "80" // Default HTTP port
	}
	path := fmt.Sprintf("/token/http/%s/%s/test", host, port)

	// Test GET request with headers
	t.Run("GET with headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com"+path, nil)
		req.Header.Set("User-Agent", "test-agent")
		req.Header.Set("Authorization", "Bearer token123")
		req.Header.Set("X-Custom", "custom-value")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		bodyStr := string(body)
		if !strings.Contains(bodyStr, "Method: GET") {
			t.Error("Expected method to be GET")
		}
		if !strings.Contains(bodyStr, "Path: /test") {
			t.Error("Expected path to be /test")
		}
		if !strings.Contains(bodyStr, "Header Authorization: Bearer token123") {
			t.Error("Expected Authorization header to be forwarded")
		}
		if !strings.Contains(bodyStr, "Header X-Custom: custom-value") {
			t.Error("Expected X-Custom header to be forwarded")
		}
	})

	// Test POST request with body
	t.Run("POST with body", func(t *testing.T) {
		postBody := `{"test": "data"}`
		req := httptest.NewRequest("POST", "http://example.com"+path, bytes.NewBufferString(postBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		bodyStr := string(body)
		if !strings.Contains(bodyStr, "Method: POST") {
			t.Error("Expected method to be POST")
		}
		if !strings.Contains(bodyStr, fmt.Sprintf("Body: %s", postBody)) {
			t.Error("Expected request body to be forwarded")
		}
	})
}

func TestXForwardedHeaders(t *testing.T) {
	mockServer := createMockTargetServer()
	defer mockServer.Close()

	client := createTestHTTPClient()
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
		port = "80" // Default HTTP port
	}
	path := fmt.Sprintf("/token/http/%s/%s/test", host, port)

	req := httptest.NewRequest("GET", "http://example.com"+path, nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Host = "proxy.example.com"

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "Header X-Forwarded-For: 192.168.1.100") {
		t.Error("Expected X-Forwarded-For header")
	}
	if !strings.Contains(bodyStr, "Header X-Forwarded-Proto: http") {
		t.Error("Expected X-Forwarded-Proto header")
	}
	if !strings.Contains(bodyStr, "Header X-Forwarded-Host: proxy.example.com") {
		t.Error("Expected X-Forwarded-Host header")
	}
}

func TestRedirectHandling(t *testing.T) {
	redirectServer := createMockRedirectServer()
	defer redirectServer.Close()

	t.Run("Redirects enabled", func(t *testing.T) {
		client := createTestHTTPClient()
		handler := createProxyHandler(client, []string{"token"}, "", true, 10, true)

		// Parse mock server URL
		serverURL, err := url.Parse(redirectServer.URL)
		if err != nil {
			t.Fatalf("Failed to parse mock server URL: %v", err)
		}

		// Extract host and port separately
		host := serverURL.Hostname()
		port := serverURL.Port()
		if port == "" {
			port = "80" // Default HTTP port
		}
		path := fmt.Sprintf("/token/http/%s/%s/redirect1", host, port)

		req := httptest.NewRequest("GET", "http://example.com"+path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 after redirect, got %d", resp.StatusCode)
		}

		bodyStr := string(body)
		if !strings.Contains(bodyStr, "Final destination after redirects") {
			t.Error("Expected to reach redirect target")
		}
	})

	t.Run("Redirects disabled", func(t *testing.T) {
		client := createTestHTTPClient()
		handler := createProxyHandler(client, []string{"token"}, "", false, 10, true)

		// Parse mock server URL
		serverURL, err := url.Parse(redirectServer.URL)
		if err != nil {
			t.Fatalf("Failed to parse mock server URL: %v", err)
		}

		// Extract host and port separately
		host := serverURL.Hostname()
		port := serverURL.Port()
		if port == "" {
			port = "80" // Default HTTP port
		}
		path := fmt.Sprintf("/token/http/%s/%s/redirect1", host, port)

		req := httptest.NewRequest("GET", "http://example.com"+path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusFound {
			t.Errorf("Expected status 302 when redirects disabled, got %d", resp.StatusCode)
		}
	})
}

func TestMaxRedirects(t *testing.T) {
	// Create a server that redirects more than the limit
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer redirectServer.Close()

	client := createTestHTTPClient()
	handler := createProxyHandler(client, []string{"token"}, "", true, 2, true) // Max 2 redirects

	// Parse mock server URL
	serverURL, err := url.Parse(redirectServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse mock server URL: %v", err)
	}

	// Extract host and port separately
	host := serverURL.Hostname()
	port := serverURL.Port()
	if port == "" {
		port = "80" // Default HTTP port
	}
	path := fmt.Sprintf("/token/http/%s/%s/loop", host, port)

	req := httptest.NewRequest("GET", "http://example.com"+path, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected status 429 after max redirects, got %d", resp.StatusCode)
	}
}

func TestErrorHandling(t *testing.T) {
	client := createTestHTTPClient()
	handler := createProxyHandler(client, []string{"token"}, "", true, 10, true)

	t.Run("Invalid target URL", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/token/https/invalid%20url/test", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status 400 for invalid URL, got %d", resp.StatusCode)
		}
	})

	t.Run("Unreachable host", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/token/http/127.0.0.1/12345/test", nil)
		w := httptest.NewRecorder()

		// Use context with timeout to prevent hanging
		ctx, cancel := context.WithTimeout(req.Context(), 100*time.Millisecond)
		defer cancel()
		req = req.WithContext(ctx)

		handler.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("Expected status 502 for unreachable host, got %d", resp.StatusCode)
		}
	})

	t.Run("Invalid protocol", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/token/ftp/example.com/test", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status 400 for invalid protocol, got %d", resp.StatusCode)
		}
	})
}

func TestHostHeader(t *testing.T) {
	mockServer := createMockTargetServer()
	defer mockServer.Close()

	client := createTestHTTPClient()
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
		port = "80" // Default HTTP port
	}
	path := fmt.Sprintf("/token/http/%s/%s/test", host, port)

	req := httptest.NewRequest("GET", "http://example.com"+path, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	bodyStr := string(body)
	expectedHost := serverURL.Host
	if !strings.Contains(bodyStr, fmt.Sprintf("Host: %s", expectedHost)) {
		t.Errorf("Expected Host header to be %s, got: %s", expectedHost, bodyStr)
	}
}

func TestCORSWithProxy(t *testing.T) {
	mockServer := createMockTargetServer()
	defer mockServer.Close()

	client := createTestHTTPClient()
	handler := createProxyHandler(client, []string{"token"}, "", true, 10, true)

	// Wrap with CORS middleware
	corsHandler := corsMiddleware(handler, "*", "GET, POST", "Content-Type")

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
	path := fmt.Sprintf("/token/http/%s/%s/test", host, port)

	t.Run("Preflight request", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "http://example.com"+path, nil)
		w := httptest.NewRecorder()
		corsHandler.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("Expected status 204 for OPTIONS, got %d", resp.StatusCode)
		}

		if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Error("Expected Access-Control-Allow-Origin: *")
		}
	})

	t.Run("Actual request with CORS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com"+path, nil)
		w := httptest.NewRecorder()
		corsHandler.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Error("Expected Access-Control-Allow-Origin: * on actual request")
		}
	})
}

func TestInvalidHTTPRequestMethod(t *testing.T) {
	client := createTestHTTPClient()
	handler := createProxyHandler(client, []string{"token"}, "", true, 10, true)

	// Parse mock server URL
	serverURL, err := url.Parse("http://example.com")
	if err != nil {
		t.Fatalf("Failed to parse mock server URL: %v", err)
	}

	// Extract host and port separately
	host := serverURL.Hostname()
	port := serverURL.Port()
	if port == "" {
		port = "80" // Default HTTP port
	}
	path := fmt.Sprintf("/token/http/%s/%s/test", host, port)

	// Create a custom request with invalid method that will cause http.NewRequest to fail
	// We need to create the request manually since httptest.NewRequest validates the method
	req := &http.Request{
		Method: "INVALID\x00METHOD", // This should cause http.NewRequest to fail
		URL: &url.URL{
			Scheme: "http",
			Host:   "example.com",
			Path:   path,
		},
		Header: make(http.Header),
		Body:   nil,
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected status 500 for invalid method, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "Failed to create request\n" {
		t.Errorf("Expected error message 'Failed to create request', got: %s", string(body))
	}
}
