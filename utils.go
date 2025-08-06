package main

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lmittmann/tint"
	"golang.org/x/term"
)

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
		// Use tint for colored output in terminal
		handler = tint.NewHandler(os.Stderr, &tint.Options{
			Level:      logLevel,
			TimeFormat: time.TimeOnly,
		})
	} else {
		// Use plain text logfmt handler for non-terminal output
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
		// From http.DefaultTransport
		Proxy:             http.ProxyFromEnvironment,
		ForceAttemptHTTP2: true,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(cfg.RequestTimeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
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
func validateToken(token string, tokenSet map[string]Empty) bool {
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
