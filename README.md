# GubinNET Web Server

GubinNET is a configurable web server written in Go with support for:
- HTTP/HTTPS serving
- Virtual hosting
- .NET application hosting
- PHP support
- Metrics monitoring (Prometheus)
- Rate limiting
- Basic authentication
- CORS
- Gzip compression
- Caching
- Static file serving and SPA fallback
- Request size limiting
- Custom error pages**
- ETag and Last-Modified headers for caching
- Proxy support
- Automatic reloading of configuration
- Built-in health checks

## Features

- Configurable via INI file
- Supports multiple virtual hosts with individual settings
- Automatic .NET application startup/shutdown
- Built-in metrics endpoint on port 9090
- Health check endpoint on port 8081
- Graceful shutdown and configuration reload
- Middleware for logging, metrics collection, and panic recovery
- Supports static file serving with MIME type detection
- Handles malicious path traversal attempts
- Rate limiting based on client IP
- CORS headers customization
- SPA fallback for single-page applications
- Customizable timeouts for requests
- Supports trusted proxies for correct client IP detection
- Automatic cleanup and management of cached files
- Custom headers like `Server` and `X-Request-ID`

## Configuration

The server reads configuration from an INI file (default: `/etc/gubinnet/config.ini`).
Main configuration options include:
- Listen ports for HTTP/HTTPS
- Max request size
- Request timeout
- Metrics and Gzip support flags
- Trusted proxies list
- Default proxy settings for upstream servers
- PHP binary path and web root configuration

Virtual host configuration includes:
- Base path and web root
- SSL certificates
- Proxy settings
- Basic auth credentials
- CORS settings
- Rate limiting
- Application mode (e.g., dotnet)
- Path to DLL for .NET applications
- Internal port for hosted applications
- SPA fallback file for frontend routing

## Usage

1. Build the server using `go build`
2. Set configuration file path using `GUBINNET_CONFIG` environment variable if needed
3. Run the executable
4. Access metrics at http://localhost:9090/metrics
5. Check health status at http://localhost:8081/health
6. Reload configuration by sending SIGHUP signal
7. Gracefully shut down using SIGTERM or SIGINT

## Logging

Logs are stored in JSON format in the specified log directory (`/etc/gubinnet/logs` by default). Each log entry includes:
- Timestamp
- Log level (INFO, WARNING, ERROR, DEBUG)
- Message
- Additional contextual fields (e.g., host, request ID, error details)

## Metrics

The following metrics are exposed:
- `http_requests_total` (counter): Tracks total HTTP requests by method, path, and status code
- `http_request_duration_seconds` (histogram): Measures request duration in seconds with configurable buckets
- `http_active_connections` (gauge): Tracks the number of active HTTP connections

## Notes

- Supports graceful shutdown on SIGTERM/SIGINT
- Reloads configuration on SIGHUP
- Automatically manages .NET application lifecycle
- Handles large file downloads with streaming
- Supports conditional requests using ETag and Last-Modified headers
- Serves custom error pages with detailed information**
- Automatically detects and prevents malicious URL paths (e.g., `../`)
- Provides detailed logging for debugging and monitoring
- Supports both gzip-compressed and uncompressed responses based on client preferences
- Manages cache entries with thread-safe operations**
- Includes middleware for panic recovery to prevent server crashes