# GubinNET – Secure Go-Based Web Server with Dynamic Module Support

GubinNET is a high-performance, secure, and modular HTTP server written in Go. It’s designed for **production-grade hosting** with built-in support for:

✅ Static file serving (SPA-ready)  
✅ Reverse proxy with SNI  
✅ Dynamic modules (C/C++, Go, Python, WASM)  
✅ Built-in DDoS protection  
✅ Prometheus + pprof monitoring  
✅ Structured logging & hot reload  

Unlike traditional proxies, GubinNET allows **secure execution of native modules** — but with **strict signing and isolation** to prevent RCE and privilege escalation.

> 🔐 **Security-first**: No dynamic `g++` compilation. All modules must be **pre-compiled and signed**.

---

## 📦 Key Features

| Feature | Description |
|--------|-------------|
| **Static Hosting** | Serve SPAs (React, Vue) with `try_files` fallback |
| **Reverse Proxy** | Forward traffic to backend services |
| **SNI / HTTPS** | TLS with per-host certificates |
| **Dynamic Modules** | Load `.so` or WASM modules (C/C++, Go, Rust) |
| **Module Signing** | Ed25519 signature verification for `.so` binaries |
| **DDoS Protection** | Rate limiting + IP banning |
| **Observability** | Prometheus `/metrics`, `pprof`, and `/healthz` |
| **Structured Logging** | JSON logs with request ID, duration, status |
| **Hot Reload** | `SIGHUP` to reload config without downtime |

---

## 🔐 Security Model

GubinNET prioritizes security over convenience:

- ❌ **No dynamic C++ compilation** – `g++` execution removed to prevent RCE.
- ✅ **Modules must be pre-compiled** – developers compile `module.cpp` → `module.so` **offline**.
- ✅ **All modules must be signed** with Ed25519 key.
- ✅ **Path traversal protection** via `safeJoin()` and strict validation.
- ✅ **Security headers**: `X-Frame-Options`, `X-XSS-Protection`, `HSTS`.
- ✅ **Isolation**: Modules run in main process but are monitored and logged.

---

## 🧩 Module System (Secure)

GubinNET supports **dynamic modules** via CGO or WASM — but only if they are **trusted and signed**.

### 1. `cgo` – C/C++ Modules (`.so`)

```ini
server_name=modules.example.com
listen_port=80
app_mode=cgo
module_path=/etc/gubinnet/modules/my_module/module.so
module_sig=/etc/gubinnet/modules/my_module/module.so.sig
use_ssl=true
cert_path=/etc/ssl/certs/modules.crt
key_path=/etc/ssl/private/modules.key
```

- Module must be compiled manually:
  ```bash
  g++ -shared -fPIC module.cpp -o module.so
  ```
- Signed with private key:
  ```bash
  openssl dgst -sha256 -sign private.pem -out module.so.sig module.so
  ```
- Server verifies signature using `/etc/gubinnet/gubinnet.pub`.

> ⚠️ No `.cpp` → `.so` compilation at runtime.

---

### 2. `wasm` – WebAssembly Modules (Future)

> Coming soon: WASM support via `wazero` for full sandboxing.

---

### 3. `proxy` – Reverse Proxy Mode

```ini
server_name=api.example.com
listen_port=80
app_mode=proxy
proxy_url=http://internal-service:8080
use_ssl=true
cert_path=/etc/ssl/certs/api.crt
key_path=/etc/ssl/private/api.key
redirect_to_https=true
```

- All traffic forwarded to backend.
- Supports SNI and HTTPS termination.

---

### 4. `static` – Static Site / SPA

```ini
server_name=spa.example.com
listen_port=80
app_mode=static
root_path=/var/www/spa
try_files=index.html
use_ssl=true
cert_path=/etc/ssl/certs/spa.crt
key_path=/etc/ssl/private/spa.key
```

- Ideal for React, Vue, Angular apps.
- Fallback to `index.html` for client-side routing.

---

## ⚙️ Installation

### 1. Clone & Build

```bash
git clone https://github.com/yourusername/gubinnet.git
cd gubinnet
go build -o gubinnet main.go
```

### 2. Create Directories

```bash
sudo mkdir -p /etc/gubinnet/{config,logs,modules}
sudo mkdir -p /var/www
```

### 3. Generate Signing Keys

```bash
# Generate Ed25519 key pair
openssl genpkey -algorithm ED25519 -out /etc/gubinnet/private.pem
openssl pkey -in /etc/gubinnet/private.pem -pubout -out /etc/gubinnet/gubinnet.pub
```

> Server requires `/etc/gubinnet/gubinnet.pub` to verify module signatures.

---

## 🛠️ Configuration Example

`/etc/gubinnet/config/example.ini`:

```ini
server_name=modules.example.com
listen_port=80
app_mode=cgo
module_path=/etc/gubinnet/modules/demo/module.so
module_sig=/etc/gubinnet/modules/demo/module.so.sig
use_ssl=true
cert_path=/etc/ssl/certs/example.com.crt
key_path=/etc/ssl/private/example.com.key
redirect_to_https=true
```

---

## 🚀 Run the Server

```bash
sudo ./gubinnet
```

Server starts on:
- `:80` – HTTP
- `:443` – HTTPS
- `:9090` – `/metrics` and `/healthz`
- `:6060` – `pprof` (profiling)

---

## 🔄 Hot Reload

Reload config without restart:

```bash
kill -HUP $(pgrep gubinnet)
```

---

## 📊 Monitoring & Debugging

### 1. Health Check
```bash
GET http://localhost:9090/healthz
→ 200 OK
```

### 2. Prometheus Metrics
```bash
GET http://localhost:9090/metrics
```

Metrics include:
- `http_requests_total`
- `http_request_duration_seconds`
- `http_active_connections`
- `module_executions_total`
- `module_errors_total`

### 3. Profiling (pprof)
```bash
# CPU profile
curl http://localhost:6060/debug/pprof/profile > profile.out

# Heap profile
curl http://localhost:6060/debug/pprof/heap > heap.out

# View with:
go tool pprof profile.out
```

---

## 🐳 Docker Support

### `Dockerfile`

```dockerfile
FROM alpine:latest AS builder
RUN apk add --no-cache gcc g++ libc-dev
WORKDIR /app
COPY . .
RUN go build -o gubinnet main.go

FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/gubinnet .
COPY --from=builder /app/config /etc/gubinnet/config
COPY --from=builder /app/modules /etc/gubinnet/modules
COPY --from=builder /app/logs /etc/gubinnet/logs
COPY --from=builder /app/gubinnet.pub /etc/gubinnet/gubinnet.pub

EXPOSE 80 443 9090 6060
CMD ["./gubinnet"]
```

### `docker-compose.yml`

```yaml
version: '3'
services:
  gubinnet:
    build: .
    ports:
      - "80:80"
      - "443:443"
      - "9090:9090"
      - "6060:6060"
    volumes:
      - ./ssl:/etc/ssl
      - ./data/config:/etc/gubinnet/config
      - ./data/modules:/etc/gubinnet/modules
      - ./data/logs:/etc/gubinnet/logs
    restart: unless-stopped
```

---

## 📁 Directory Structure

```bash
/etc/gubinnet/
├── config/               # .ini configuration files
│   └── site1.ini
├── modules/              # Pre-compiled, signed modules
│   └── demo/
│       ├── module.so
│       └── module.so.sig
├── logs/
│   ├── access.log        # JSON-formatted access logs
│   └── antiddos.log      # Blocked IPs
└── gubinnet.pub          # Public key for module verification
```

---

## 📋 Logging

Logs are written in structured JSON:

```json
{
  "timestamp": "2025-04-05T10:00:00Z",
  "level": "INFO",
  "message": "Request processed",
  "method": "GET",
  "path": "/modules/demo",
  "status": 200,
  "duration": 0.012,
  "remote": "192.168.1.100",
  "user_agent": "curl/7.68.0",
  "request_id": "a1b2c3d4-e5f6-7890-g1h2-i3j4k5l6m7n8"
}
```

Log rotation: daily.

---

## 🛡 Anti-DDoS Protection

- **Rate limit**: 100 requests/sec per IP.
- **Ban duration**: 60 seconds.
- Logs blocked IPs in `/etc/gubinnet/logs/antiddos.log`.

Configurable via code (in future: config file).

---

## 📄 License

MIT License – see [LICENSE](LICENSE)

---

## 🚀 Want to Contribute?

We welcome:
- WASM module support
- External module runner (sandboxed processes)
- JWT auth middleware
- OpenTelemetry tracing

Open an issue or submit a PR!

---

> ✅ **Keep it fast.**  
> ✅ **Keep it secure.**  
> ✅ **One proxy to rule them all.**
