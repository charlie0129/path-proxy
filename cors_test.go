package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSMiddleware(t *testing.T) {
	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "test response")
	})

	// Wrap with CORS middleware
	corsHandler := corsMiddleware(testHandler, "*", "GET, POST", "Content-Type")

	// Test preflight request
	req := httptest.NewRequest("OPTIONS", "http://example.com/test", nil)
	w := httptest.NewRecorder()
	corsHandler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("Expected status 204 for OPTIONS, got %d", resp.StatusCode)
	}

	// Check CORS headers
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Error("Expected Access-Control-Allow-Origin: *")
	}
	if resp.Header.Get("Access-Control-Allow-Methods") != "GET, POST" {
		t.Error("Expected Access-Control-Allow-Methods: GET, POST")
	}
	if resp.Header.Get("Access-Control-Allow-Headers") != "Content-Type" {
		t.Error("Expected Access-Control-Allow-Headers: Content-Type")
	}

	// Test actual request
	req = httptest.NewRequest("GET", "http://example.com/test", nil)
	w = httptest.NewRecorder()
	corsHandler.ServeHTTP(w, req)

	resp = w.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for GET, got %d", resp.StatusCode)
	}
	if string(body) != "test response" {
		t.Errorf("Expected body 'test response', got '%s'", string(body))
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Error("Expected Access-Control-Allow-Origin: * on actual request")
	}
}

func TestCORSMiddlewareWithCustomValues(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Test with custom CORS values
	corsHandler := corsMiddleware(testHandler, "https://example.com", "GET, POST, PUT", "Content-Type, Authorization")

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()
	corsHandler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.Header.Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Error("Expected custom origin")
	}
	if resp.Header.Get("Access-Control-Allow-Methods") != "GET, POST, PUT" {
		t.Error("Expected custom methods")
	}
	if resp.Header.Get("Access-Control-Allow-Headers") != "Content-Type, Authorization" {
		t.Error("Expected custom headers")
	}
}
