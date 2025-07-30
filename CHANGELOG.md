# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v1.6.0] - 2025-07-30

### ✅ Added
- **Security headers**: `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Strict-Transport-Security`.
- **Module signature verification** using Ed25519 to prevent unauthorized or tampered `.so` modules.
- **Health and metrics endpoints**:
  - `/healthz` – returns 200 OK for liveness checks.
  - `/metrics` – exposes Prometheus metrics on port `:9090`.
- **Profiling support** via `pprof` on port `:6060`.
- **Safe path joining** with `safeJoin()` to prevent path traversal attacks.
- **Docker compatibility** – ready for containerized deployment.
- **Improved logging**:
  - JSON-formatted logs with structured fields.
  - Auto-rotation of access logs every 24 hours.
- **Enhanced security middleware** with stricter regex filtering for malicious paths.

### 🔒 Removed
- **Dynamic C++ compilation at runtime** (`g++` execution) – removed `compileCppModule()` due to critical RCE vulnerability.
- **Direct `exec.Command("g++")`** – no longer allowed in production to prevent arbitrary code execution.

### 🛠 Fixed
- **Path traversal vulnerability** – replaced `filepath.Join` + `filepath.Clean` with `safeJoin()` to enforce root directory isolation.
- **Insecure module loading** – now requires valid `.so.sig` signature before loading any module.
- **Weak DDoS protection** – improved tracking and banning logic with proper mutex locking and cleanup.
- **Unsafe handling of `Host` header** – now uses `strings.Split` to safely extract hostname.
- **Potential nil pointer dereference** in `serveFile()` when `fileInfo` is not provided.

### ⚙️ Changed
- **Modules must now be precompiled** – developers must manually compile `module.cpp` → `module.so` and sign it.
- **Public key requirement** – server now requires `/etc/gubinnet/gubinnet.pub` for module verification.
- **Configuration structure** – moved metrics and pprof to dedicated ports (`:9090`, `:6060`) to avoid conflicts.
- **CGO module isolation** – although still in-process, modules are now verified and logged more strictly.
- **Error pages** – updated version to `GubinNET/1.6.0` in HTML templates.
- **Anti-DDoS log path** – now uses `/etc/gubinnet/logs/antiddos.log` instead of `/tmp`.

### 📦 Dependencies
- Added:
  - `github.com/google/uuid` – for unique request IDs.
  - `github.com/prometheus/client_golang` – for enhanced metrics.
- Updated Go modules to latest secure versions.

### 🧪 Improved Observability
- **Prometheus metrics**:
  - `http_requests_total`
  - `http_request_duration_seconds`
  - `http_active_connections`
  - `module_executions_total`
  - `module_errors_total`
- **Structured logging** with request ID, duration, status, and user agent.
- **pprof endpoint** for CPU, heap, and goroutine profiling.

### 🐳 DevOps & Deployment
- Ready for **Docker** and **Kubernetes**:
  - Multi-stage Docker builds supported.
  - Health checks via `/healthz`.
  - Metrics ready for Prometheus scraping.
- Supports **systemd** integration with graceful shutdown.

---

## [v1.5.1] - 2025-04-05

*(Original version before major security overhaul)*

### Added
- Dynamic C++ module compilation (`g++` on-the-fly).
- CGO module loading via `dlopen`.
- Virtual hosts with SNI support.
- Try-files for SPA routing.
- Prometheus metrics (basic).
- Anti-DDoS rate limiting.

### Known Issues
- Risk of RCE via `g++` execution.
- No module signing or verification.
- Path traversal possible in edge cases.
- No health check endpoint.
- No pprof or deep observability.

---