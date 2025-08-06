package main

import (
	"net/http"
	"testing"
)

func TestCopyHeaders_FilterHopByHopHeaders(t *testing.T) {
	tests := []struct {
		name           string
		sourceHeaders  http.Header
		expectedCopied map[string][]string
		expectedDropped []string
	}{
		{
			name: "Standard hop-by-hop headers should be dropped",
			sourceHeaders: http.Header{
				"Content-Type":       {"application/json"},
				"User-Agent":        {"test-agent"},
				"Connection":        {"keep-alive"},
				"Upgrade":          {"websocket"},
				"Transfer-Encoding": {"chunked"},
				"Authorization":    {"Bearer token123"},
			},
			expectedCopied: map[string][]string{
				"Content-Type":    {"application/json"},
				"User-Agent":     {"test-agent"},
				"Authorization":  {"Bearer token123"},
			},
			expectedDropped: []string{"Connection", "Upgrade", "Transfer-Encoding"},
		},
		{
			name: "Connection header with additional hop-by-hop headers",
			sourceHeaders: http.Header{
				"Content-Type": {"text/html"},
				"Connection":   {"close, X-Custom-Hop, X-Another-Hop"},
				"X-Custom-Hop": {"should-be-dropped"},
				"X-Another-Hop": {"also-dropped"},
				"X-Regular":    {"should-remain"},
			},
			expectedCopied: map[string][]string{
				"Content-Type": {"text/html"},
				"X-Regular":    {"should-remain"},
			},
			expectedDropped: []string{"Connection", "X-Custom-Hop", "X-Another-Hop"},
		},
		{
			name: "No hop-by-hop headers",
			sourceHeaders: http.Header{
				"Content-Type":   {"application/xml"},
				"Accept":         {"application/xml"},
				"X-Custom-Header": {"custom-value"},
			},
			expectedCopied: map[string][]string{
				"Content-Type":    {"application/xml"},
				"Accept":          {"application/xml"},
				"X-Custom-Header": {"custom-value"},
			},
			expectedDropped: []string{},
		},
		{
			name: "Empty headers",
			sourceHeaders: http.Header{},
			expectedCopied: map[string][]string{},
			expectedDropped: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create destination header
			dst := make(http.Header)
			
			// Call the function being tested
			copyHeaders(dst, tt.sourceHeaders)
			
			// Verify copied headers
			for key, expectedValues := range tt.expectedCopied {
				if values, exists := dst[key]; !exists {
					t.Errorf("Header %s should be copied but wasn't", key)
				} else if !headerValuesEqual(values, expectedValues) {
					t.Errorf("Header %s values mismatch. Got %v, want %v", key, values, expectedValues)
				}
			}
			
			// Verify dropped headers
			for _, droppedHeader := range tt.expectedDropped {
				if _, exists := dst[droppedHeader]; exists {
					t.Errorf("Header %s should be dropped but was copied", droppedHeader)
				}
			}
			
			// Verify no extra headers were copied
			if len(dst) != len(tt.expectedCopied) {
				t.Errorf("Wrong number of headers copied. Got %d, want %d", len(dst), len(tt.expectedCopied))
				t.Errorf("Copied headers: %v", dst)
			}
		})
	}
}

// Helper function to compare header values
func headerValuesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}