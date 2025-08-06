package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/charlie0129/path-proxy/pkg/version"
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
    path-proxy -p 8080`,
	Run: run,
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

func run(cmd *cobra.Command, args []string) {
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
}
