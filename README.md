# Path-Proxy

A specialized reverse proxy that forwards HTTP requests by extracting target information from the URL path. Unlike traditional reverse proxies that use routing rules or configuration files, this proxy encodes the target protocol, domain, and port directly in the request URL.

## Use Cases

This is useful for dynamic routing scenarios where you want to access different services without needing to configure each one explicitly. It's especially handy for environments where you cannot configure HTTP proxies, such as browsers or certain client applications. You can use add a path prefix to your requests to route them through this proxy.

1. **Development**: Access remote APIs during development without CORS issues
2. **Testing**: Test services behind firewalls by exposing them through a single endpoint
3. **Integration**: Provide a unified access point for multiple services
4. **Demo**: Create demo environments where services are accessed through a proxy

Note that you should use regular forward proxies (e.g. using HTTP_PROXY/HTTPS_PROXY environment variables) or reverse proxies (e.g. Traefik, NGINX, Caddy) if possible, as they are more common. This proxy is designed for specific use cases where you need to route requests dynamically without configuration, or your environment does not allow for traditional proxy setups.

## Features

- **Two routing modes**: Token-based authentication or open access
- **Custom path prefix**: Optional path prefix for all requests
- **Protocol support**: HTTP and HTTPS
- **Header manipulation**: Automatically sets Host header and adds X-Forwarded-* headers
- **Redirect handling**: Configurable redirect following with maximum limits
- **Body streaming**: Efficient streaming of request/response bodies
- **Token management**: Support for CLI tokens and token files
- **Connection pooling**: Reuses HTTP connections for improved performance
- **Graceful shutdown**: Clean shutdown with active request completion
- **HTTP proxy support**: Automatically respects system proxy settings

## Installation

### Download from Releases

Head to the [Releases](https://github.com/charlie0129/path-proxy/releases) page and download the latest binary for your platform:

- `linux` (Linux): amd64 (x86_64), arm64 (aarch64)
- `darwin` (macOS): amd64 (x86_64), arm64 (aarch64)
- `windows` (Windows): amd64 (x86_64), arm64 (aarch64)

Extract the archive and place the binary in your PATH (usually `/usr/local/bin` on Unix systems).

### Docker Containers

The image is available on both GitHub Container Registry and DockerHub:

- GHCR: ghcr.io/charlie0129/path-proxy
- DockerHub: charlie0129/path-proxy

You can run the proxy using Docker:

```bash
docker run --rm -it -p 8080:8080 ghcr.io/charlie0129/path-proxy:latest
```

### Build from Source

To build from source, ensure you have Go installed (version 1.24 or later). Clone the repository and run:

```bash
make
```

You should see the `path-proxy` binary in `bin/`.

## Usage

### Basic Usage

Start the proxy server on port 8080:

```bash
./path-proxy -p 8080
```

### With Custom Path Prefix

```bash
# Set a custom path prefix
./path-proxy -p 8080 --path-prefix myprefix/v1
```

### With Tokens

```bash
# Using CLI flags
./path-proxy -p 8080 -t my-secret-token -t another-token

# Using a token file
./path-proxy -p 8080 --token-file tokens.txt
```

The token file format is simple - one token per line, empty lines and lines starting with `#` are ignored:

```
# Production tokens
prod-token-123
api-token-456

# Development tokens
dev-token-789
```

### All Options

```bash
./path-proxy --help
```

```
      --add-headers                   Add X-Forwarded-* headers (default true)
      --cors-headers string           CORS Headers value (default "Content-Type, Authorization")
      --cors-methods string           CORS Methods header value (default "GET, POST, PUT, DELETE, OPTIONS")
      --cors-origin string            CORS Origin header value (default "*")
      --disable-keep-alives           Disable HTTP keep-alives
      --enable-cors                   Enable CORS headers
      --follow                        Follow HTTP redirects (default true)
  -h, --help                          help for path-proxy
      --idle-conn-timeout int         Idle connection timeout in seconds (default 90)
      --log-level string              Log level (debug, info, warn, error) (default "info")
      --max-idle-conns int            Maximum idle connections (default 100)
      --max-idle-conns-per-host int   Maximum idle connections per host (default 10)
      --max-redirect int              Maximum number of redirects to follow (default 10)
  -p, --port int                      Port to listen on (default 8080)
      --path-prefix string            Custom path prefix for all requests (e.g., myprefix/v1)
      --shutdown-timeout int          Graceful shutdown timeout in seconds (default 30)
      --tls-handshake-timeout int     TLS handshake timeout in seconds (default 10)
  -t, --token strings                 Access token (can be specified multiple times)
      --token-file string             File containing tokens (one per line)
  -v, --version                       version for path-proxy
```

## How It Works

### URL Format

The proxy extracts the target URL from the request path:

#### Without Tokens (Open Mode)

```
/<prefix>/<protocol>/<domain>/<port>/<path>
```

Example:
```
GET /https/github.com/443/charlie0129/path-proxy
    → GET https://github.com:443/charlie0129/path-proxy

GET /myprefix/v1/https/github.com/443/charlie0129/path-proxy
    → GET https://github.com:443/charlie0129/path-proxy
```

#### With Tokens (Secure Mode)

```
/<prefix>/<token>/<protocol>/<domain>/<port>/<path>
```

Example:
```
GET /my-token/https/api.github.com/443/users/charlie0129
    → GET https://api.github.com:443/users/charlie0129

GET /myprefix/v1/my-token/https/api.github.com/443/users/charlie0129
    → GET https://api.github.com:443/users/charlie0129
```

### Examples

1. **Accessing GitHub (HTTPS)**

   You must keep the port even if it is the default port for the protocol (443 for HTTPS, 80 for HTTP):

   ```bash
   # Without token
   curl http://localhost:8080/https/github.com/443/charlie0129/path-proxy
   
   # With token
   curl http://localhost:8080/my-token/https/github.com/443/charlie0129/path-proxy
   
   # With custom path prefix
   curl http://localhost:8080/myprefix/v1/https/github.com/443/charlie0129/path-proxy
   
   # With path prefix and token
   curl http://localhost:8080/myprefix/v1/my-token/https/github.com/443/charlie0129/path-proxy
   ```

2. **Accessing HTTP service on non-standard port**
   ```bash
   curl http://localhost:8080/http/local-dev/3000/api/users
   curl http://localhost:8080/myprefix/v1/http/local-dev/3000/api/users
   ```

3. **API requests with headers**
   ```bash
   curl -H "Authorization: Bearer abc123" \
        http://localhost:8080/token/https/api.example.com/443/v1/data
   curl -H "Authorization: Bearer abc123" \
        http://localhost:8080/myprefix/v1/token/https/api.example.com/443/v1/data
   ```

4. **POST requests with body**
   ```bash
   curl -X POST \
        -H "Content-Type: application/json" \
        -d '{"name": "test"}' \
        http://localhost:8080/token/https/api.example.com/443/create
   curl -X POST \
        -H "Content-Type: application/json" \
        -d '{"name": "test"}' \
        http://localhost:8080/myprefix/v1/token/https/api.example.com/443/create
   ```

5. **With connection pooling for high traffic**
   ```bash
   ./path-proxy --max-idle-conns 200 --max-idle-conns-per-host 20 --idle-conn-timeout 120
   ```

6. **With custom shutdown timeout**
   ```bash
   ./path-proxy --shutdown-timeout 60 --token-file ./tokens.txt
   ```

7. **With custom path prefix**
   ```bash
   ./path-proxy --path-prefix api/v1
   ./path-proxy --path-prefix proxy --token-file ./tokens.txt
   ```

## Header Handling

The proxy automatically modifies headers:

1. **Host Header**: Set to match the target domain and port
2. **X-Forwarded-For**: Appends the client's IP address
3. **X-Forwarded-Proto**: Set to "http" or "https" based on the original request
4. **X-Forwarded-Host**: Set to the original Host header

You can disable adding X-Forwarded-* headers with `--add-headers=false`.

## Redirect Handling

By default, the proxy follows HTTP redirects up to 10 times. You can customize this behavior:

```bash
# Disable redirect following
./path-proxy --follow=false

# Set custom redirect limit
./path-proxy --max-redirect=5
```

When redirects are disabled, the proxy returns redirect responses (3xx) as-is to the client.

## Security Considerations

1. **Tokens**: Use strong, randomly generated tokens
2. **Token File**: Ensure proper file permissions (600 recommended)
3. **Network**: Consider binding to specific interfaces instead of 0.0.0.0
4. **HTTPS**: The proxy itself serves HTTP; for HTTPS, use a reverse proxy like Traefik, NGINX or Caddy in front

## Error Handling

The proxy returns appropriate HTTP status codes:
- `400 Bad Request`: Invalid URL format
- `401 Unauthorized`: Invalid or missing token
- `502 Bad Gateway`: Target server unreachable
- `504 Gateway Timeout`: Target server timeout

## Performance

- Minimal overhead with direct streaming
- No buffering of request/response bodies
- Configurable connection handling

### Connection Pooling

The proxy implements HTTP connection pooling to improve performance by reusing TCP connections for multiple requests to the same host. This reduces TCP handshake overhead and improves latency.

```bash
# Configure connection pooling
./path-proxy --max-idle-conns 100 --max-idle-conns-per-host 10 --idle-conn-timeout 90
```

Available connection pooling options:
- `--max-idle-conns`: Maximum number of idle connections (default: 100)
- `--max-idle-conns-per-host`: Maximum idle connections per host (default: 10)
- `--idle-conn-timeout`: Idle connection timeout in seconds (default: 90)
- `--tls-handshake-timeout`: TLS handshake timeout in seconds (default: 10)
- `--disable-keep-alives`: Disable HTTP keep-alives if needed

### Graceful Shutdown

The proxy supports graceful shutdown to ensure active requests are completed before the server exits. When receiving SIGINT (Ctrl+C) or SIGTERM, the proxy:

1. Stops accepting new connections
2. Allows active requests to complete
3. Closes idle connections in the pool
4. Exits cleanly after timeout or completion

```bash
# Configure shutdown timeout
./path-proxy --shutdown-timeout 30
```

Use `--shutdown-timeout` to control how long the server waits for active requests to complete (default: 30 seconds).

## HTTP Proxy Support

The proxy automatically respects standard HTTP proxy environment variables:

- `HTTP_PROXY`: Proxy server for HTTP requests
- `HTTPS_PROXY`: Proxy server for HTTPS requests  
- `NO_PROXY`: Comma-separated list of hosts that should bypass the proxy

Examples:

```bash
# Set HTTP proxy for all requests
export HTTP_PROXY=http://proxy.example.com:8080
export HTTPS_PROXY=http://proxy.example.com:8080

# Set proxy with authentication
export HTTP_PROXY=http://user:pass@proxy.example.com:8080

# Exclude certain hosts from proxy
export NO_PROXY=localhost,127.0.0.0/8,internal.example.com

# Start the proxy - it will automatically use the environment variables
./path-proxy
```

## Contributing

Feel free to submit issues and pull requests. Please ensure:
1. Code follows Go conventions
2. Add tests for new features
3. Update documentation as needed

## License

This project is open source and available under the GPLv2 License.
