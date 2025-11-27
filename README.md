# GubinNET - Advanced Go Web Server with PostgreSQL Virtual Hosts

GubinNET is a high-performance web server written in Go that serves as an alternative to Nginx. It supports multiple technologies including HTML, PHP, Node.js, and .NET, with comprehensive security features. Virtual host configurations are now stored in PostgreSQL for dynamic management.

## Features

- **Multi-Technology Support**: Serve HTML, PHP, Node.js, and .NET applications
- **Advanced Security**:
  - Anti-DDoS protection with rate limiting
  - Bot detection and blocking
  - XSS protection
  - Directory traversal prevention
  - Content filtering
- **URL Rewriting**: Apache mod_rewrite-like functionality
- **Database-Driven Configuration**: Virtual hosts stored in PostgreSQL
- **Dynamic Virtual Hosts**: Add, modify, or remove virtual hosts without server restart
- **High Performance**: Built on Go's efficient HTTP server

## Architecture

GubinNET is built with a modular architecture:

- `main.go`: Entry point and server orchestration
- `config.go`: Configuration management with PostgreSQL integration
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
   go get github.com/lib/pq
   ```

## Configuration

GubinNET uses a JSON configuration file (`gubinnet.conf`) that contains only database access settings. Virtual host configurations are stored in PostgreSQL.

Example `gubinnet.conf`:
```json
{
  "database": {
    "host": "localhost",
    "port": 5432,
    "user": "gubinnet",
    "password": "gubinnet",
    "dbname": "gubinnet",
    "sslmode": "disable"
  }
}
```

### PostgreSQL Database Setup

Create the virtual hosts table in your PostgreSQL database:

```sql
CREATE TABLE virtual_hosts (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    public_dir VARCHAR(500) NOT NULL,
    port VARCHAR(10) DEFAULT '80',
    enabled BOOLEAN DEFAULT true,
    ssl_required BOOLEAN DEFAULT false,
    ssl_cert VARCHAR(500),
    ssl_key VARCHAR(500)
);

-- Example virtual host entries
INSERT INTO virtual_hosts (domain, public_dir, port, enabled) VALUES
('example.com', '/var/www/example', '80', true),
('test.com', '/var/www/test', '80', true);
```

## Usage

1. Set up your PostgreSQL database with virtual host configurations
2. Configure `gubinnet.conf` with database connection details
3. Run the server:
   ```bash
   go run *.go
   ```

## Technology Support

### HTML/Static Files
- Standard HTML, CSS, JavaScript files
- Automatic index file detection (index.html, index.htm, etc.)
- Virtual host-specific document roots

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
