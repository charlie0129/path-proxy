package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lmittmann/tint"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/charlie0129/path-proxy/pkg/version"
)

const (
	// Supported protocols
	ProtocolHTTP  = "http"
	ProtocolHTTPS = "https"
)

// Config holds the configuration for the reverse proxy
type Config struct {
	Port                int      // Port to listen on
	Tokens              []string // Access tokens for authentication
	TokenFile           string   // File containing tokens (one per line)
	PathPrefix          string   // Custom path prefix for all requests
	Follow              bool     // Whether to follow HTTP redirects
	MaxRedirect         int      // Maximum number of redirects to follow
	AddHeaders          bool     // Whether to add X-Forwarded-* headers
	LogLevel            string   // Log level (debug, info, warn, error)
	EnableCORS          bool     // Whether to enable CORS headers
	CORSOrigin          string   // CORS Origin header value
	CORSMethods         string   // CORS Methods header value
	CORSHeaders         string   // CORS Headers value
	MaxIdleConns        int      // Maximum idle connections
	MaxIdleConnsPerHost int      // Maximum idle connections per host
	IdleConnTimeout     int      // Idle connection timeout in seconds
	TLSHandshakeTimeout int      // TLS handshake timeout in seconds
	DisableKeepAlives   bool     // Disable HTTP keep-alives
	ShutdownTimeout     int      // Shutdown timeout in seconds
	RequestTimeout      int      // Request timeout in seconds
}

var defaultConfig = Config{
	Port:                8080,
	Tokens:              []string{},
	TokenFile:           "",
	PathPrefix:          "",
	Follow:              true,
	MaxRedirect:         10,
	AddHeaders:          true,
	LogLevel:            "info",
	EnableCORS:          false,
	CORSOrigin:          "*",
	CORSMethods:         "GET, POST, PUT, DELETE, OPTIONS",
	CORSHeaders:         "Content-Type, Authorization",
	MaxIdleConns:        100,
	MaxIdleConnsPerHost: 10,
	IdleConnTimeout:     90,
	TLSHandshakeTimeout: 10,
	DisableKeepAlives:   false,
	ShutdownTimeout:     5,
	RequestTimeout:      30,
}

var cfg = defaultConfig

// Create the root Cobra command
var rootCmd = &cobra.Command{
	Use:     "path-proxy",
	Version: version.Version,
	Short:   "A reverse proxy that forwards requests based on URL path",
	Long: `Path-Proxy is a specialized reverse proxy that forwards requests 
by extracting target information from the URL path. It supports both token-based 
and token-less routing modes, with optional custom path prefix.

URL Format:
  Without tokens: /<prefix>/<protocol>/<domain>/<port>/path
  With tokens:    /<prefix>/<token>/<protocol>/<domain>/<port>/path

Examples:
  # Start proxy on port 8080
  path-proxy -p 8080
  
  # With custom path prefix
  path-proxy -p 8080 --path-prefix myprefix/v1
  
  # With tokens from CLI
  path-proxy -p 8080 -t mytoken1 -t mytoken2
  
  # With tokens from file
  path-proxy -p 8080 --token-file ./tokens.txt
  
  # With connection pooling
  path-proxy --max-idle-conns 200 --max-idle-conns-per-host 20
  
  # Example requests:
  #   GET /https/github.com/443/some/file.txt
  #   → GET https://github.com/some/file.txt
  #   
  #   GET /myprefix/v1/https/github.com/443/some/file.txt
  #   → GET https://github.com/some/file.txt
  #   
  #   GET /myprefix/v1/my-token/https/api.example.com/443/v1/users
  #   → GET https://api.example.com/v1/users

HTTP Proxy Support:
  The proxy automatically respects standard HTTP proxy environment variables:
  - HTTP_PROXY: Proxy server for HTTP requests
  - HTTPS_PROXY: Proxy server for HTTPS requests
  - NO_PROXY: Comma-separated list of hosts to bypass proxy
  
  Example:
    export HTTP_PROXY=http://proxy.example.com:8080
    export HTTPS_PROXY=http://proxy.example.com:8080
    path-proxy -p 8080

  # With custom request timeout
  path-proxy --request-timeout 60`,
	Run: func(cmd *cobra.Command, args []string) {
		// Start with tokens from CLI flags
		tokens := cfg.Tokens

		// If a token file is specified, read tokens from it
		if cfg.TokenFile != "" {
			fileTokens, err := readTokensFromFile(cfg.TokenFile)
			if err != nil {
				slog.Error("Error reading token file", "error", err)
				os.Exit(1)
			}
			tokens = append(tokens, fileTokens...)
		}

		// Configure logger based on log level
		configureLogger(cfg.LogLevel)

		// Create HTTP client with connection pooling
		client := createHTTPClient(&cfg)

		// Create the proxy handler with all configuration
		handler := createProxyHandler(client, tokens, cfg.PathPrefix, cfg.AddHeaders)

		// Add CORS middleware if enabled
		if cfg.EnableCORS {
			handler = corsMiddleware(handler, cfg.CORSOrigin, cfg.CORSMethods, cfg.CORSHeaders)
		}

		// Start the HTTP server with graceful shutdown
		addr := fmt.Sprintf(":%d", cfg.Port)
		server := &http.Server{
			Addr:    addr,
			Handler: handler,
		}

		slog.Info("Starting server",
			"addr", addr,
			"token_mode", map[bool]string{true: "enabled", false: "disabled"}[len(tokens) > 0],
			"path_prefix", cfg.PathPrefix,
			"follow_redirects", cfg.Follow,
			"max_redirects", cfg.MaxRedirect,
			"add_forward_headers", cfg.AddHeaders,
			"log_level", cfg.LogLevel,
			"cors_enabled", cfg.EnableCORS,
			"shutdown_timeout", cfg.ShutdownTimeout)

		// Channel to listen for errors
		serverErrors := make(chan error, 1)

		// Start the server
		go func() {
			slog.Info("Server listening on " + addr)
			serverErrors <- server.ListenAndServe()
		}()

		// Wait for interrupt signal
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-quit:
			slog.Info("Shutting down server...")

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.ShutdownTimeout)*time.Second)
			defer cancel()

			// Gracefully shutdown the server
			if err := server.Shutdown(ctx); err != nil {
				slog.Error("Server forced to shutdown", "error", err)
				os.Exit(1)
			}

			// Close idle connections in the HTTP client
			if transport, ok := client.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
			}

			slog.Info("Server exited")
			return

		case err := <-serverErrors:
			slog.Error("Server failed", "error", err)
			os.Exit(1)
		}
	},
}

func init() {
	f := rootCmd.Flags()

	// Define command line flags
	f.IntVarP(&cfg.Port, "port", "p", cfg.Port, "Port to listen on")
	f.StringSliceVarP(&cfg.Tokens, "token", "t", cfg.Tokens, "Access token (can be specified multiple times)")
	f.StringVar(&cfg.TokenFile, "token-file", cfg.TokenFile, "File containing tokens (one per line)")
	f.StringVar(&cfg.PathPrefix, "path-prefix", cfg.PathPrefix, "Custom path prefix for all requests (e.g., myprefix/v1)")
	f.BoolVar(&cfg.Follow, "follow", cfg.Follow, "Follow HTTP redirects")
	f.IntVar(&cfg.MaxRedirect, "max-redirect", cfg.MaxRedirect, "Maximum number of redirects to follow")
	f.BoolVar(&cfg.AddHeaders, "add-headers", cfg.AddHeaders, "Add X-Forwarded-* headers")
	f.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level (debug, info, warn, error)")
	f.BoolVar(&cfg.EnableCORS, "enable-cors", cfg.EnableCORS, "Enable CORS headers")
	f.StringVar(&cfg.CORSOrigin, "cors-origin", cfg.CORSOrigin, "CORS Origin header value when CORS is enabled")
	f.StringVar(&cfg.CORSMethods, "cors-methods", cfg.CORSMethods, "CORS Methods header value when CORS is enabled")
	f.StringVar(&cfg.CORSHeaders, "cors-headers", cfg.CORSHeaders, "CORS Headers value when CORS is enabled")
	f.IntVar(&cfg.MaxIdleConns, "max-idle-conns", cfg.MaxIdleConns, "Maximum idle connections")
	f.IntVar(&cfg.MaxIdleConnsPerHost, "max-idle-conns-per-host", cfg.MaxIdleConnsPerHost, "Maximum idle connections per host")
	f.IntVar(&cfg.IdleConnTimeout, "idle-conn-timeout", cfg.IdleConnTimeout, "Idle connection timeout in seconds")
	f.IntVar(&cfg.TLSHandshakeTimeout, "tls-handshake-timeout", cfg.TLSHandshakeTimeout, "TLS handshake timeout in seconds")
	f.BoolVar(&cfg.DisableKeepAlives, "disable-keep-alives", cfg.DisableKeepAlives, "Disable HTTP keep-alives")
	f.IntVar(&cfg.ShutdownTimeout, "shutdown-timeout", cfg.ShutdownTimeout, "Graceful shutdown timeout in seconds")
	f.IntVar(&cfg.RequestTimeout, "request-timeout", cfg.RequestTimeout, "Request timeout in seconds")
}

func main() {

	// Execute the command
	if err := rootCmd.Execute(); err != nil {
		slog.Error("Command execution failed", "error", err)
		os.Exit(1)
	}
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

// configureLogger sets up the slog handler with the specified log level
func configureLogger(level string) {
	var logLevel slog.Level

	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		// Use a temporary logger for the warning
		tempLogger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
		tempLogger.Warn("Invalid log level, defaulting to info", "level", level)
		logLevel = slog.LevelInfo
	}

	var handler slog.Handler

	if term.IsTerminal(int(os.Stderr.Fd())) {
		handler = tint.NewHandler(os.Stderr, &tint.Options{
			Level:      logLevel,
			TimeFormat: time.TimeOnly,
		})
	} else {
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: logLevel,
		})
	}

	slog.SetDefault(slog.New(handler))
}

// createHTTPClient creates an HTTP client with connection pooling
func createHTTPClient(cfg *Config) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:     time.Duration(cfg.IdleConnTimeout) * time.Second,
		TLSHandshakeTimeout: time.Duration(cfg.TLSHandshakeTimeout) * time.Second,
		DisableKeepAlives:   cfg.DisableKeepAlives,
		// Use default proxy from environment
		Proxy: http.ProxyFromEnvironment,
	}

	// Log connection pool configuration
	slog.Info("HTTP client configured with connection pooling",
		"max_idle_conns", cfg.MaxIdleConns,
		"max_idle_conns_per_host", cfg.MaxIdleConnsPerHost,
		"idle_conn_timeout", cfg.IdleConnTimeout,
		"tls_handshake_timeout", cfg.TLSHandshakeTimeout,
		"disable_keep_alives", cfg.DisableKeepAlives)

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.RequestTimeout) * time.Second, // Overall request timeout
	}

	if cfg.Follow {
		// Configure client to follow redirects
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.MaxRedirect {
				return fmt.Errorf("stopped after %d redirects", cfg.MaxRedirect)
			}
			return nil
		}
	} else {
		// Disable following redirects
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client
}

// readTokensFromFile reads tokens from a file, ignoring empty lines and comments
func readTokensFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	//nolint:errcheck
	defer file.Close()

	var tokens []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments (lines starting with #)
		if line != "" && !strings.HasPrefix(line, "#") {
			tokens = append(tokens, line)
		}
	}

	return tokens, scanner.Err()
}

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

// loggingResponseWriter wraps http.ResponseWriter to capture status code and content length
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode    int
	contentLength int64
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	n, err := lrw.ResponseWriter.Write(b)
	lrw.contentLength += int64(n)
	return n, err
}

// validateToken validates the provided token against the token set
func validateToken(token string, tokenSet map[string]struct{}) bool {
	_, ok := tokenSet[token]
	return ok
}

// isValidPort checks if a port number is valid (1-65535)
func isValidPort(portStr string) bool {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return port > 0 && port <= 65535
}

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

	parts := strings.SplitN(strings.TrimPrefix(cleanPath, "/"), "/", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid URL format: expected /%s/<proto>/<domain>/<port>/path", pathPrefix)
	}

	proto := strings.ToLower(parts[0])
	domain := parts[1]
	portStr := parts[2]

	// Validate protocol
	if proto != ProtocolHTTP && proto != ProtocolHTTPS {
		return nil, fmt.Errorf("unsupported protocol: %s (only http and https are supported)", proto)
	}

	// Validate domain is not empty
	if domain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}

	// Extract port and path if present
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

// createProxyHandler creates the main HTTP handler for the reverse proxy
func createProxyHandler(client *http.Client, tokens []string, pathPrefix string, addHeaders bool) http.Handler {
	// Convert tokens to a set for O(1) lookup
	tokenSet := make(map[string]struct{})
	for _, token := range tokens {
		tokenSet[token] = struct{}{}
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

		// Parse target URL
		targetURL, err := parseTargetURL(targetPath, pathPrefix)
		if err != nil {
			slog.Warn("Failed to parse target URL",
				"error", err,
				"path", requestPath,
				"remote_addr", r.RemoteAddr)
			http.Error(w, "Invalid target URL", http.StatusBadRequest)
			return
		}

		// Log request forwarding
		slog.Debug("Forwarding request",
			"method", r.Method,
			"path", requestPath,
			"target", targetURL.String(),
			"remote_addr", r.RemoteAddr)

		// Log connection pool stats in debug mode
		if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
			if transport, ok := client.Transport.(*http.Transport); ok {
				slog.Debug("Connection pool stats",
					"target_host", targetURL.Host,
					"max_idle_conns", transport.MaxIdleConns,
					"max_idle_conns_per_host", transport.MaxIdleConnsPerHost,
					"idle_conn_timeout", transport.IdleConnTimeout)
			}
		}

		handleRequestWithRedirects(client, w, r, targetURL, addHeaders)
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
	addHeaders bool,
) {
	// Create a new request for the target
	targetReq, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		slog.Error("Failed to create request",
			"error", err,
			"method", r.Method,
			"target", targetURL.String())
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// Copy headers
	maps.Copy(targetReq.Header, r.Header)

	// Set Host header
	targetReq.Host = targetURL.Host

	// Add X-Forwarded-* headers if enabled
	if addHeaders {
		if targetReq.Header.Get("X-Forwarded-For") == "" {
			targetReq.Header.Set("X-Forwarded-For", r.RemoteAddr)
		} else {
			targetReq.Header.Set("X-Forwarded-For",
				strings.Join([]string{targetReq.Header.Get("X-Forwarded-For"), r.RemoteAddr}, ", "))
		}
		targetReq.Header.Set("X-Forwarded-Proto", "http")
		if r.TLS != nil {
			targetReq.Header.Set("X-Forwarded-Proto", "https")
		}
		targetReq.Header.Set("X-Forwarded-Host", r.Host)
	}

	// Send the request
	resp, err := client.Do(targetReq)
	if err != nil {
		slog.Error("Failed to proxy request",
			"error", err,
			"target", targetURL.String(),
			"remote_addr", r.RemoteAddr)
		http.Error(w, "Failed to proxy request", http.StatusBadGateway)
		return
	}
	//nolint:errcheck
	defer resp.Body.Close()

	// Copy response headers
	maps.Copy(w.Header(), resp.Header)

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	//nolint:errcheck // no need to check because we cannot do anything with the error
	io.Copy(w, resp.Body)
}
