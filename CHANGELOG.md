### 📝 Changelog – May 15, 2025

#### ✅ General Improvements
- **Refactored `gubinnet.go`** into a single, self-contained file for easier deployment and management.
- **Merged external modules** such as `logger` and `antiddos` directly into the main source file to eliminate dependency issues and simplify maintenance.

#### 🧹 Code Cleanup & Fixes
- **Fixed incorrect line breaks** in the PHP-CGI handler — corrected from `\r\n\r\n` parsing errors to ensure proper header-body separation.
- **Updated logger calls** to match the expected signature: `logger.Info("message", map[string]interface{})`.
- **Reorganized code blocks**, added comments, and improved overall readability and maintainability.

#### 🔐 Security Enhancements
- **Enhanced security middleware** to block access to known malicious paths such as `.env`, `/shell`, and WordPress setup scripts.
- **Added request ID propagation** across all logs for better traceability of requests through systems.
- **Improved error handling** with consistent logging of remote IPs, user agents, and unique request IDs.

#### ⚙️ Logging
- **Structured JSON logging** implemented throughout the application for easy parsing by log collectors (e.g., ELK, Loki).
- **Automatic daily log rotation** ensures clean and manageable log files.
- Logs now include rich metadata:
  - Method, path, status, duration
  - Remote IP, user agent
  - Request ID for tracing

#### 🛡 Anti-DDoS Integration
- **Integrated rate limiting** to protect against DDoS attacks.
- **IP banning mechanism** triggers when clients exceed a configurable number of requests per second.
- **Logs blocked IPs** and banned connection attempts for auditing and monitoring purposes.

#### 📁 Configuration Management
- **Improved config parser** to skip invalid or missing root paths gracefully without crashing.
- **Support for hot-reloading configuration** via the `SIGHUP` signal — no need to restart the server.

#### 🌐 Server Functionality
- **Dynamic virtual host management**: servers can be started, stopped, and reloaded on-the-fly.
- **SNI-based HTTPS support**: each virtual host can have its own TLS certificate.
- **PHP-CGI execution support** with full environment variable setup and header parsing.
- **Reverse proxy improvements**:
  - Full header forwarding
  - Streaming response body
  - Configurable timeout and streaming behavior

#### 📦 Build & Deployment
- The entire application is now **fully self-contained** and can be compiled with a single command:
  ```bash
  go build -o gubinnet gubinnet.go
  ```
- **Minimal dependencies**: only requires Prometheus and Google UUID libraries — everything else uses Go standard libraries.
- Easy to deploy as a standalone binary with systemd, Docker, or orchestration tools.

---

This version represents a significant step forward in making GubinNET a robust, secure, and production-ready reverse proxy and web server.
