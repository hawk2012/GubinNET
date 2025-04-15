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

## Features

- Configurable via INI file
- Supports multiple virtual hosts with individual settings
- Automatic .NET application startup/shutdown
- Built-in metrics endpoint on port 9090
- Health check endpoint on port 8081
- Graceful shutdown and configuration reload
- Middleware for logging, metrics collection, and panic recovery

## Configuration

The server reads configuration from an INI file (default: /etc/gubinnet/config.ini).
Main configuration options include:
- Listen ports for HTTP/HTTPS
- Max request size
- Request timeout
- Metrics and Gzip support flags
- Trusted proxies list

Virtual host configuration includes:
- Base path and web root
- SSL certificates
- Proxy settings
- Basic auth credentials
- CORS settings
- Rate limiting

## Usage

1. Build the server using `go build`
2. Set configuration file path using GUBINNET_CONFIG environment variable if needed
3. Run the executable
4. Access metrics at http://localhost:9090/metrics
5. Check health status at http://localhost:8081/health

## Logging

Logs are stored in JSON format in the specified log directory (/etc/gubinnet/logs by default).

## Metrics

The following metrics are exposed:
- http_requests_total (counter)
- http_request_duration_seconds (histogram)
- http_active_connections (gauge)

## Notes

- Supports graceful shutdown on SIGTERM/SIGINT
- Reloads configuration on SIGHUP
- Automatically manages .NET application lifecycle