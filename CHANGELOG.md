### 📝 Changelog – April 5, 2025

#### ✅ General Improvements
- Refactored `gubinnet.go` into a single, self-contained file for easier deployment and management.
- Merged external modules (`logger` and `antiddos`) directly into the main source file to eliminate dependency issues.

#### 🧹 Code Cleanup & Fixes
- Fixed incorrect line breaks in the PHP-CGI handler (`\r\n\r\n` instead of `\r\n\r\n` issue).
- Updated logger calls to match the expected signature: `logger.Info("message", map[string]interface{})`.
- Improved readability and maintainability by reorganizing code blocks and adding comments.

#### 🔐 Security Enhancements
- Enhanced security middleware to block known malicious paths (e.g., `.env`, `/shell`, WordPress setup paths).
- Added proper request ID logging for better traceability and debugging.

#### ⚙️ Logging
- Implemented structured JSON logging with automatic log rotation.
- All logs now include detailed metadata such as method, path, status, duration, IP, user agent, and request ID.

#### 🛡 Anti-DDoS Integration
- Integrated DDoS protection via rate limiting.
- Added middleware that bans IPs exceeding the allowed number of requests per second.
- Logs blocked IPs and banned connections for monitoring and analysis.

#### 📁 Configuration Management
- Improved config parser to skip invalid or missing root paths gracefully.
- Added support for hot-reloading configuration on `SIGHUP`.

#### 🌐 Server Functionality
- Enhanced virtual host management with dynamic start/stop of HTTP servers.
- SNI-based HTTPS support using certificates defined per virtual host.
- Proper handling of PHP files using `php-cgi` with environment variables and header parsing.
- Proxy support improved with full header forwarding and response streaming.

#### 📦 Build & Deployment
- The entire application can now be compiled with a single command:
  ```bash
  go build -o gubinnet gubinnet.go
  ```
- No need for separate package installations or dependencies outside standard libraries (except Prometheus and Google UUID).
