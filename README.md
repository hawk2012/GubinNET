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
- **Nginx Integration**: Generate and sync virtual host configurations to nginx
- **High Performance**: Built on Go's efficient HTTP server

## Architecture

GubinNET is built with a modular architecture:

- `main.go`: Entry point, CLI commands, and server orchestration
- `config.go`: Configuration management with PostgreSQL integration and CRUD for virtual hosts
- `nginx_handler.go`: Nginx configuration generation and management
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
3. Build the binary:
   ```bash
   go build -o gubinnet
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

### Starting the Server

```bash
# Start with default configuration
./gubinnet server

# Start with custom port
./gubinnet server -port 3000

# Start with custom public directory
./gubinnet server -public /var/www/html
```

### Managing Virtual Hosts

```bash
# List all virtual hosts
./gubinnet hosts -list

# Add a new virtual host
./gubinnet hosts -add -domain example.com -public /var/www/example

# Add a virtual host with SSL
./gubinnet hosts -add -domain secure.example.com -public /var/www/secure -ssl -cert /etc/ssl/certs/secure.crt -key /etc/ssl/private/secure.key

# Enable a virtual host
./gubinnet hosts -enable -domain example.com

# Disable a virtual host
./gubinnet hosts -disable -domain example.com

# Remove a virtual host
./gubinnet hosts -remove -domain example.com
```

### Nginx Integration

GubinNET can generate nginx configuration files and sync virtual hosts from the database to nginx.

```bash
# Sync all virtual hosts from database to nginx
./gubinnet nginx -sync

# Generate nginx config for a specific domain
./gubinnet generate -domain example.com

# Generate and save to file
./gubinnet generate -domain example.com -output /etc/nginx/sites-available/example.com

# Test nginx configuration
./gubinnet nginx -test

# Reload nginx
./gubinnet nginx -reload

# Show nginx status
./gubinnet nginx -status

# List nginx virtual hosts
./gubinnet nginx -list
```

### API Endpoints

When running with database configuration, GubinNET provides REST API for managing virtual hosts:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/hosts` | List all virtual hosts |
| POST | `/api/v1/hosts` | Create a new virtual host |
| GET | `/api/v1/hosts/{id}` | Get a specific virtual host |
| PUT | `/api/v1/hosts/{id}` | Update a virtual host |
| DELETE | `/api/v1/hosts/{id}` | Delete a virtual host |
| POST | `/api/v1/hosts/{domain}/enable` | Enable a virtual host |
| POST | `/api/v1/hosts/{domain}/disable` | Disable a virtual host |
| POST | `/api/v1/nginx/sync` | Sync hosts to nginx |
| GET | `/api/v1/nginx/config/{domain}` | Get nginx config for domain |
| POST | `/api/v1/nginx/reload` | Reload nginx |
| GET | `/api/v1/nginx/status` | Get nginx status |
| GET | `/api/v1/nginx/test` | Test nginx configuration |

#### Example API Usage

```bash
# List all virtual hosts
curl http://localhost:8080/api/v1/hosts

# Create a new virtual host
curl -X POST http://localhost:8080/api/v1/hosts \
  -H "Content-Type: application/json" \
  -d '{"domain":"newsite.com","public_dir":"/var/www/newsite","port":"80","enabled":true}'

# Enable a virtual host
curl -X POST http://localhost:8080/api/v1/hosts/newsite.com/enable

# Get nginx configuration
curl http://localhost:8080/api/v1/nginx/config/newsite.com

# Sync to nginx
curl -X POST http://localhost:8080/api/v1/nginx/sync
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

## Nginx Configuration Features

The nginx handler generates optimized configurations including:

- **Gzip compression** for text, CSS, JS, and other compressible types
- **Security headers** (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, CSP)
- **Static file caching** with configurable expiration
- **PHP-FPM integration** for PHP applications
- **SSL/TLS configuration** with modern cipher suites
- **HTTP/2 support** for HTTPS connections
- **Rate limiting** protection
- **Reverse proxy** configurations

### Generated Nginx Config Example

```nginx
# Virtual host for example.com
# Generated by GubinNET at 2024-01-15 10:30:00

server {
    listen 80;
    server_name example.com;
    root /var/www/example;
    index index.html index.htm index.php;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        try_files $uri $uri/ =404;
    }

    # PHP handling
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
    }

    # Static files caching
    location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
        expires 30d;
    }
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
