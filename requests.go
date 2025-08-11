package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
)

const (
	// Supported protocols
	ProtocolHTTP  = "http"
	ProtocolHTTPS = "https"
)

type Empty struct{}

var (
	// Standard hop-by-hop headers defined in RFC 7230
	hopByHopHeaders = map[string]Empty{
		"Connection":          {},
		"Keep-Alive":          {},
		"Proxy-Authenticate":  {},
		"Proxy-Authorization": {},
		"TE":                  {},
		"Trailers":            {},
		"Transfer-Encoding":   {},
		"Upgrade":             {},
	}
)

// extractPathPrefix removes the configured path prefix from the request path
func extractPathPrefix(requestPath, pathPrefix string) (string, error) {
	// Clean the path first to handle multiple slashes
	cleanPath := path.Clean(requestPath)

	if pathPrefix == "" {
		return cleanPath, nil
	}

	// Normalize path prefix
	normalizedPrefix := strings.Trim(pathPrefix, "/")

	// Build the expected prefix pattern
	var expectedPrefix string
	if normalizedPrefix != "" {
		expectedPrefix = "/" + normalizedPrefix
	}

	// Check if the path starts with the expected prefix
	if !strings.HasPrefix(cleanPath, expectedPrefix) {
		return "", fmt.Errorf("path does not match configured prefix: %s", pathPrefix)
	}

	// Extract the remaining path
	remainingPath := strings.TrimPrefix(cleanPath, expectedPrefix)

	// Handle empty remaining path
	if remainingPath == "" {
		remainingPath = "/"
	} else if !strings.HasPrefix(remainingPath, "/") && remainingPath != "/" {
		// Ensure remaining path starts with a slash (unless it's just "/")
		remainingPath = "/" + remainingPath
	}

	return remainingPath, nil
}

// parseTargetURL parses the target URL from the path components
func parseTargetURL(targetPath, pathPrefix string) (*url.URL, error) {
	// Clean the path to handle multiple slashes
	cleanPath := path.Clean(targetPath)
	if cleanPath != targetPath {
		slog.Debug("Path cleaned", "original", targetPath, "cleaned", cleanPath)
	}

	// <proto>/<domain>/<port>/path
	parts := strings.SplitN(strings.TrimPrefix(cleanPath, "/"), "/", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid URL format: expected /%s/<proto>/<domain>/<port>/path", pathPrefix)
	}

	proto := strings.ToLower(parts[0])
	domain := parts[1]
	portStr := parts[2] // Currently, this includes the port and path. We will split it later.

	// Validate protocol
	if proto != ProtocolHTTP && proto != ProtocolHTTPS {
		return nil, fmt.Errorf("unsupported protocol: %s (only http and https are supported)", proto)
	}

	// Validate domain is not empty
	if domain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}

	// Extract port and path from the portStr
	var targetURLPath string
	if portAndPath := strings.SplitN(portStr, "/", 2); len(portAndPath) > 1 {
		portStr = portAndPath[0]
		targetURLPath = "/" + portAndPath[1]
	}

	// Validate port number
	if !isValidPort(portStr) {
		return nil, fmt.Errorf("invalid port number: %s (must be 1-65535)", portStr)
	}

	// Additional validation: check for path traversal attempts in domain
	if strings.Contains(domain, "..") || strings.Contains(domain, "/") {
		return nil, fmt.Errorf("invalid domain format")
	}

	target := fmt.Sprintf("%s://%s:%s", proto, domain, portStr)
	target += targetURLPath

	parsedURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %w", err)
	}

	// Ensure the parsed URL matches what we expect
	if parsedURL.Scheme != proto || parsedURL.Hostname() != domain || parsedURL.Port() != portStr {
		return nil, fmt.Errorf("URL parsing validation failed")
	}

	return parsedURL, nil
}

// copyHeaders copies headers from source to destination, excluding hop-by-hop headers
func copyHeaders(dst, src http.Header) {
	// Check Connection header for additional hop-by-hop headers
	var additionalHopByHopHeaders = make(map[string]Empty)
	if connectionHeaders := src.Values("Connection"); len(connectionHeaders) > 0 {
		for _, connHeader := range connectionHeaders {
			for _, h := range strings.Split(connHeader, ",") {
				additionalHopByHopHeaders[strings.TrimSpace(h)] = Empty{}
			}
		}
	}

	// Copy headers, excluding hop-by-hop headers
	for key, values := range src {
		if _, ok := hopByHopHeaders[key]; ok {
			continue
		}
		if _, ok := additionalHopByHopHeaders[key]; ok {
			continue
		}
		dst[key] = values
	}
}

// createProxyHandler creates the main HTTP handler for the reverse proxy
func createProxyHandler(client *http.Client, tokens []string, pathPrefix string, removeForwardHeaders bool) http.Handler {
	// Convert tokens to a set for O(1) lookup
	tokenSet := make(map[string]Empty)
	for _, token := range tokens {
		tokenSet[token] = Empty{}
	}

	// Normalize path prefix - remove leading/trailing slashes and ensure it starts without a slash
	if pathPrefix != "" {
		pathPrefix = strings.Trim(pathPrefix, "/")
	}

	// Create the proxy handler
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath := r.URL.Path

		// Extract path prefix
		remainingPath, err := extractPathPrefix(r.URL.Path, pathPrefix)
		if err != nil {
			slog.Warn("Path prefix validation failed",
				"path", requestPath,
				"prefix", pathPrefix,
				"remote_addr", r.RemoteAddr)
			http.Error(w, fmt.Sprintf("Invalid path prefix. Expected: /%s/...", pathPrefix), http.StatusBadRequest)
			return
		}

		// Determine target path and validate token if needed
		var targetPath string
		if len(tokenSet) > 0 {
			// Token mode: /<token>/<proto>/<domain>/<port>/path
			// Clean the remaining path first
			cleanRemainingPath := path.Clean(remainingPath)

			parts := strings.SplitN(strings.TrimPrefix(cleanRemainingPath, "/"), "/", 4)
			if len(parts) < 4 || parts[0] == "" || parts[1] == "" || parts[2] == "" || parts[3] == "" {
				slog.Warn("Invalid URL format with token",
					"path", requestPath,
					"remote_addr", r.RemoteAddr,
					"expected_format", fmt.Sprintf("/%s/<token>/<proto>/<domain>/<port>/path", pathPrefix))
				http.Error(w, fmt.Sprintf("Invalid URL format. Expected: /%s/<token>/<proto>/<domain>/<port>/path", pathPrefix), http.StatusBadRequest)
				return
			}

			token := parts[0]
			if !validateToken(token, tokenSet) {
				slog.Warn("Invalid token",
					"token", token,
					"path", requestPath,
					"remote_addr", r.RemoteAddr)
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Reconstruct path without token
			targetPath = "/" + strings.Join(parts[1:], "/")
		} else {
			// No token mode: /<proto>/<domain>/<port>/path
			targetPath = remainingPath
		}

		// Deep copy the original URL to avoid modifying the original request.
		targetURL := deepCopyURL(r.URL)

		// Parse target URL in the path.
		parsedURL, err := parseTargetURL(targetPath, pathPrefix)
		if err != nil {
			slog.Warn("Failed to parse target URL",
				"error", err,
				"path", requestPath,
				"remote_addr", r.RemoteAddr)
			http.Error(w, "Invalid target URL", http.StatusBadRequest)
			return
		}

		// Put the parsed URL into the target URL
		targetURL.Scheme = parsedURL.Scheme
		targetURL.Host = parsedURL.Host
		targetURL.Path = parsedURL.Path

		// Log request forwarding
		slog.Debug("Forwarding request",
			"method", r.Method,
			"path", requestPath,
			"target", targetURL.String(),
			"remote_addr", r.RemoteAddr)

		handleRequestWithRedirects(client, w, r, targetURL, removeForwardHeaders)
	})

	// Wrap with logging middleware
	return loggingMiddleware(proxyHandler)
}

// handleRequestWithRedirects manually handles HTTP requests with optional redirect following
func handleRequestWithRedirects(
	client *http.Client,
	w http.ResponseWriter,
	r *http.Request,
	targetURL *url.URL,
	removeForwardHeaders bool,
) {

	// Create a new request with context for the target
	targetReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), r.Body)
	if err != nil {
		slog.Error("Failed to create request",
			"error", err,
			"method", r.Method,
			"target", targetURL.String())
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// Copy headers, excluding hop-by-hop headers
	copyHeaders(targetReq.Header, r.Header)

	// Set Host header
	targetReq.Host = targetURL.Host

	// Add X-Forwarded-* headers if enabled
	if !removeForwardHeaders {
		if targetReq.Header.Get("X-Forwarded-For") == "" {
			targetReq.Header.Set("X-Forwarded-For", r.RemoteAddr)
		} else {
			targetReq.Header.Set("X-Forwarded-For",
				strings.Join([]string{targetReq.Header.Get("X-Forwarded-For"), r.RemoteAddr}, ", "))
		}

		// Check if X-Forwarded-Proto already exists
		if targetReq.Header.Get("X-Forwarded-Proto") == "" {
			// Only set it if we're the first proxy
			if r.TLS != nil {
				targetReq.Header.Set("X-Forwarded-Proto", "https")
			} else {
				targetReq.Header.Set("X-Forwarded-Proto", "http")
			}
		}

		// Check if X-Forwarded-Host already exists
		if targetReq.Header.Get("X-Forwarded-Host") == "" {
			// Only set it if we're the first proxy
			targetReq.Header.Set("X-Forwarded-Host", r.Host)
		}
	}

	// Send the request
	resp, err := client.Do(targetReq)
	if err != nil {
		// Check for context cancellation
		if errors.Is(err, context.Canceled) {
			slog.Info("Request cancelled by client",
				"remote_addr", r.RemoteAddr,
				"target", targetURL.String())
			return
		}
		if errors.Is(err, context.DeadlineExceeded) {
			slog.Info("Request timeout",
				"remote_addr", r.RemoteAddr,
				"target", targetURL.String())
			http.Error(w, "Request timeout", http.StatusGatewayTimeout)
			return
		}
		slog.Error("Failed to proxy request",
			"error", err,
			"target", targetURL.String(),
			"remote_addr", r.RemoteAddr)
		http.Error(w, "Failed to proxy request", http.StatusBadGateway)
		return
	}
	//nolint:errcheck
	defer resp.Body.Close()

	// Copy response headers, excluding hop-by-hop headers
	copyHeaders(w.Header(), resp.Header)

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	//nolint:errcheck // no need to check because we cannot do anything with the error
	io.Copy(w, resp.Body)
}

func deepCopyURL(orig *url.URL) *url.URL {
	if orig == nil {
		return nil
	}

	cp := *orig // Copy all fields

	// Deep copy User if it exists
	if orig.User != nil {
		if password, ok := orig.User.Password(); ok {
			cp.User = url.UserPassword(orig.User.Username(), password)
		} else {
			cp.User = url.User(orig.User.Username())
		}
	}

	return &cp
}
