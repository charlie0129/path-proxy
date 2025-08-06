package main

import (
	"log/slog"
	"net/http"
	"time"
)

// loggingMiddleware wraps an http.Handler to add access logging
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap the response writer to capture status code and content length
		lrw := &loggingResponseWriter{w, http.StatusOK, 0}

		// Call the next handler
		next.ServeHTTP(lrw, r)

		// Log the access
		duration := time.Since(start)
		slog.Info("Finished request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
			"status", lrw.statusCode,
			"duration_ms", float64(duration.Microseconds())/1000.0,
			"content_length", lrw.contentLength)
	})
}

// corsMiddleware adds CORS headers to responses
func corsMiddleware(next http.Handler, origin, methods, headers string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", methods)
		w.Header().Set("Access-Control-Allow-Headers", headers)

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}
