# GubinNET – Go-based Reverse Proxy with PHP, Node.js, .NET and Static Hosting

GubinNET is a lightweight, high-performance reverse proxy and web server written in Go. It supports:

✅ Serving static files (SPA-ready)  
✅ Running ASP.NET Core applications  
✅ Running Node.js applications  
✅ Proxied requests to external backend services  
✅ Built-in DDoS protection  
✅ Prometheus metrics  
✅ HTTPS with SNI support  
✅ Enhanced security features  

It's ideal for hosting multiple applications on the same server while maintaining performance, security, and simplicity.

---

## 📦 Features

| Feature | Description |
|--------|-------------|
| **Reverse Proxy** | Route traffic to any HTTP backend service |
| **Static File Server** | Serve HTML/CSS/JS files or host SPAs like React/Vue/Angular |
| **ASP.NET Core Hosting** | Run `.dll` apps directly from config |
| **Node.js Hosting** | Launch `app.js` or other scripts automatically |
| **HTTPS / TLS** | Full SNI support with certificate per domain |
| **DDoS Protection** | Rate-limiting and IP banning |
| **Structured Logging** | JSON logs with rich metadata |
| **Prometheus Metrics** | Expose `/metrics` endpoint for monitoring |
| **Hot Reload** | Send `SIGHUP` to reload configuration without restart |
| **Enhanced Security** | Path traversal protection, header filtering, request size limits |

---

## 🛡 Enhanced Security Features

GubinNET now includes several enhanced security measures:

- **Path Traversal Protection**: Prevents directory traversal attacks using `filepath.Rel()` validation
- **Secure Proxy Handling**: Validates target URLs, filters unsafe headers, limits redirects, and enforces request size limits
- **Information Leakage Prevention**: Hides internal error details in production environments
- **Request Size Limiting**: Limits request body size to prevent resource exhaustion
- **Header Filtering**: Blocks potentially dangerous headers during proxy operations
- **Cache Size Management**: Prevents cache-related DoS attacks with size limits and eviction policies

## 🧩 AppModes

You can define the behavior of each virtual host using `.ini` configuration files located in `/etc/gubinnet/config/`.

### 1. `dotnet` – ASP.NET Core Applications

```ini
server_name=api.example.net
listen_port=80
app_mode=dotnet
dll_path=/var/www/app/MyApp.dll
internal_port=5000
use_ssl=true
cert_path=/etc/ssl/certs/api.example.net.crt
key_path=/etc/ssl/private/api.example.net.key
redirect_to_https=true
```

- Automatically starts `dotnet MyApp.dll` internally.
- Requests are proxied to `localhost:5000`.
- Environment variables set:
  ```bash
  ASPNETCORE_URLS=http://0.0.0.0:5000
  ASPNETCORE_ENVIRONMENT=Production
  ```

---

### 2. `nodejs` – Node.js Applications

```ini
server_name=node-app.local
listen_port=80
app_mode=nodejs
script_path=/var/www/nodeapp/app.js
internal_port=3000
use_ssl=true
cert_path=/etc/ssl/certs/node-app.crt
key_path=/etc/ssl/private/node-app.key
redirect_to_https=true
```

- Runs `node app.js` as child process.
- Routes all requests to `localhost:3000`.

---

### 3. `proxy` – Reverse Proxy Mode

```ini
server_name=proxy.example.com
listen_port=80
app_mode=proxy
proxy_url=http://internal-api:8080
use_ssl=true
cert_path=/etc/ssl/certs/proxy.example.com.crt
key_path=/etc/ssl/private/proxy.example.com.key
redirect_to_https=true
```

- All incoming requests are forwarded to `http://internal-api:8080`.

---

### 4. `static` – Static Site Hosting

```ini
server_name=my-spa-site.local
listen_port=80
app_mode=static
root_path=/var/www/my-spa
try_files=index.html
use_ssl=true
cert_path=/etc/ssl/certs/my-spa-site.crt
key_path=/etc/ssl/private/my-spa-site.key
redirect_to_https=true
```

- Serves files from `/var/www/my-spa`
- Fallback to `index.html` for SPA routing

---

## ⚙️ Installation

### 1. Clone the repo

```bash
git clone https://github.com/yourusername/gubinnet.git
cd gubinnet
```

### 2. Build the binary

```bash
go build -o gubinnet gubinnet.go
```

### 3. Create directories

```bash
sudo mkdir -p /etc/gubinnet/config
sudo mkdir -p /etc/gubinnet/logs
```

### 4. Place your `.ini` config files inside `/etc/gubinnet/config`

---

## 🛠️ Configuration Examples

### ✅ ASP.NET Core

```ini
server_name=api.example.net
listen_port=80
app_mode=dotnet
dll_path=/var/www/app/MyApp.dll
internal_port=5000
use_ssl=true
cert_path=/etc/ssl/certs/api.example.net.crt
key_path=/etc/ssl/private/api.example.net.key
redirect_to_https=true
```

### ✅ Node.js

```ini
server_name=node-app.local
listen_port=80
app_mode=nodejs
script_path=/var/www/nodeapp/app.js
internal_port=3000
use_ssl=true
cert_path=/etc/ssl/certs/node-app.crt
key_path=/etc/ssl/private/node-app.key
redirect_to_https=true
```

### ✅ Reverse Proxy

```ini
server_name=proxy.example.com
listen_port=80
app_mode=proxy
proxy_url=http://internal-api:8080
use_ssl=true
cert_path=/etc/ssl/certs/proxy.example.com.crt
key_path=/etc/ssl/private/proxy.example.com.key
redirect_to_https=true
```

### ✅ Static Website / SPA

```ini
server_name=my-spa-site.local
listen_port=80
app_mode=static
root_path=/var/www/my-spa
try_files=index.html
use_ssl=true
cert_path=/etc/ssl/certs/my-spa-site.crt
key_path=/etc/ssl/private/my-spa-site.key
redirect_to_https=true
```

---

## 🚀 Run the server

```bash
./gubinnet
```

The server will start and load all hosts defined in `.ini` files.

---

## 🔄 Hot Reload

To reload configuration without restarting:

```bash
kill -HUP $(pgrep gubinnet)
```

---

## 📊 Monitoring

Metrics are available at:

```
http://localhost/metrics
```

Supports:
- Total requests
- Request duration
- Active connections

---

## 🔐 Security

- Blocks known malicious paths:
  ```
  .env, /shell, /wordpress/wp-admin/setup-config.php, /device.rsp
  ```
- Logs every request with:
  - Method, path, status
  - Remote IP, User-Agent
  - Unique request ID

---

## 🐳 Docker Support

Use this `Dockerfile`:

```dockerfile
FROM golang:1.21
WORKDIR /app
COPY . .
RUN go build -o gubinnet gubinnet.go
CMD ["./gubinnet"]
```

And this `docker-compose.yml`:

```yaml
version: '3'
services:
  gubinnet:
    build: .
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /etc/gubinnet:/etc/gubinnet
```

---

## 📁 Directory Structure

```
/etc/gubinnet/
├── config/
│   └── myapp.ini
└── logs/
    ├── access.log
    └── antiddos.log
```

---

## 📋 Logs

Logs are written in structured JSON format by default:

```
{
  "timestamp": "2025-04-05T10:00:00Z",
  "level": "INFO",
  "message": "Request processed",
  "method": "GET",
  "path": "/",
  "status": "200",
  "remote": "192.168.1.1",
  "user_agent": "curl/7.68.0",
  "request_id": "abc123"
}
```

Log rotation happens daily.

---

## 🛡 Anti-DDoS

Built-in rate limiting:

- Default: 100 requests/sec
- Ban duration: 60 seconds
- Logs blocked IPs in `/etc/gubinnet/logs/antiddos.log`

---

## 📄 License

MIT License – see [LICENSE](LICENSE)

---

## 🚀 Want to contribute?

Feel free to submit PRs or open issues for feature suggestions and bug reports.

---

> ✅ Keep it simple.  
> ✅ Run everything behind one fast proxy.  
> ✅ No need for Nginx or Apache anymore.
> ✅ Modern admin panel for easy management.
> ✅ SQLite-based configuration for enhanced security.
