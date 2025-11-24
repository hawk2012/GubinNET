# GubinNET - Advanced Go Web Server

GubinNET is a high-performance web server written in Go that serves as an alternative to Nginx. It supports multiple technologies including HTML, PHP, Node.js, and .NET, with comprehensive security features.

## Features

- **Multi-Technology Support**: Serve HTML, PHP, Node.js, and .NET applications
- **Advanced Security**:
  - Anti-DDoS protection with rate limiting
  - Bot detection and blocking
  - XSS protection
  - Directory traversal prevention
  - Content filtering
- **URL Rewriting**: Apache mod_rewrite-like functionality
- **Configurable**: JSON-based configuration system
- **High Performance**: Built on Go's efficient HTTP server

## Architecture

GubinNET is built with a modular architecture:

- `main.go`: Entry point and server orchestration
- `config.go`: Configuration management
- `security.go`: Security features including Anti-DDoS and bot protection
- `rewrite.go`: URL rewriting engine
- `html_handler.go`: Static file serving
- `php_handler.go`: PHP execution support
- `nodejs_handler.go`: Node.js execution support
- `dotnet_handler.go`: .NET application support

## Installation

1. Make sure you have Go installed (version 1.16 or higher)
2. Install dependencies:
   ```bash
   go mod init gubinnet
   go get github.com/gorilla/mux
   ```

## Configuration

GubinNET uses a JSON configuration file (`config.json`). If the file doesn't exist, default settings will be used.

Example configuration:
```json
{
  "port": "8080",
  "public_dir": "public",
  "rewrite_rules": {
    "/api/(.*)": "/internal/api/$1",
    "/blog/(.*)": "/wp-content/$1",
    "/images/(.*)": "/assets/images/$1"
  },
  "antiddos": {
    "enabled": true,
    "max_requests": 100,
    "window_seconds": 60,
    "block_duration": 10,
    "enable_captcha": false,
    "challenge_enabled": true
  },
  "allowed_bots": [
    "googlebot", "bingbot", "slurp", 
    "duckduckbot", "baiduspider", "yandex"
  ],
  "blocked_ips": [],
  "allowed_ips": [],
  "max_file_size": 10485760,
  "timeout": 30
}
```

## Usage

1. Create a `public` directory (or your configured public directory)
2. Place your web files in the public directory
3. Run the server:
   ```bash
   go run *.go
   ```

## Technology Support

### HTML/Static Files
- Standard HTML, CSS, JavaScript files
- Automatic index file detection (index.html, index.htm, etc.)

### PHP
- Execute PHP files directly
- Environment variables passed from HTTP request
- Security checks to prevent unauthorized access

### Node.js
- Execute JavaScript files with Node.js
- Environment variables passed from HTTP request
- Security checks to prevent unauthorized access

### .NET
- Execute .NET applications (DLLs, EXEs)
- Automatic build and run for project files
- Proxy requests to running .NET applications

## Security Features

### Anti-DDoS
- Configurable rate limiting
- IP-based request counting
- Temporary IP blocking for excessive requests

### Bot Protection
- Detection of common bots and crawlers
- Configurable list of allowed bots
- JavaScript challenge for suspicious requests

### XSS Protection
- Automatic header injection for XSS prevention
- Input sanitization
- Content Security Policy headers

### General Security
- Directory traversal prevention
- File extension validation
- Access control to sensitive files

## URL Rewriting

GubinNET supports Apache mod_rewrite-like functionality:

- Regular expression-based rules
- Redirect and rewrite options
- Query string preservation
- Configurable through JSON configuration

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
