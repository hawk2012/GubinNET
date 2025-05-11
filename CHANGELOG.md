# Changelog

All notable changes to the GubinNET project will be documented in this file.

---

## [1.5.1] - 2025-06-05

### Added
1. **PHP Request Handling via FastCGI**:
   - Implemented support for executing PHP scripts through FastCGI (default port `9000`).
   - Added checks for the existence of PHP files before processing.
   - Implemented a mechanism to copy headers and responses between the client and PHP-FPM.

2. **Resolved 500 Error for PHP Sites**:
   - Fixed an issue with incorrect PHP request handling that previously caused a 500 error.
   - Added logs for diagnosing errors during PHP script execution.

3. **Support for Modern PHP Practices (2025)**:
   - Added support for API-First architecture via `try_files` configuration.
   - Implemented automatic request routing for Laravel applications (via `index.php`).

4. **Enhanced Security**:
   - Added mechanisms to protect against SQL injections and XSS attacks through middleware.
   - Implemented blocking of suspicious requests (e.g., `.env`, `/shell`).

5. **Performance Optimization**:
   - Added a caching mechanism for static files to improve server performance.
   - Implemented Gzip compression support for text files (HTML, CSS, JS).

6. **Horizontal Scaling**:
   - Added support for SNI (Server Name Indication) to handle multiple SSL certificates on a single IP address.

7. **Logging and Monitoring**:
   - Improved log format for easier analysis.
   - Added unique request identifiers (`X-Request-ID`) for tracing.
   - Integrated Prometheus metrics for server performance monitoring:
     - `http_requests_total`: Total number of HTTP requests.
     - `http_request_duration_seconds`: Request processing time.
     - `http_active_connections`: Number of active connections.

8. **Error Handling**:
   - Added error pages for various scenarios:
     - "Host Not Found" page for non-existent hosts.
     - "File Not Found" page for missing files.
     - "Access Denied" page for blocked requests.

9. **Hot Configuration Reload**:
   - Implemented the ability to reload configuration via the `SIGHUP` signal.

---

### Changed
1. **Configuration Structure**:
   - Added new parameters to support PHP and SSL:
     - `use_ssl`: Enable HTTPS.
     - `redirect_to_https`: Automatic redirection from HTTP to HTTPS.
     - `proxy_url`: Support for request proxying.

2. **Middleware**:
   - Reworked middleware for clearer separation of functionality:
     - `securityMiddleware`: Protection against suspicious requests.
     - `loggingMiddleware`: Logging of all requests.
     - `metricsMiddleware`: Collection of metrics for monitoring.

3. **File Caching**:
   - Improved the caching mechanism for static files:
     - Added file modification time checks for cache updates.
     - Implemented support for `ETag` and `Last-Modified` headers.

4. **Static File Handling**:
   - Improved logic for finding `index.html` in directories.
   - Added support for multiple index file variants (`index.html`, `index.htm`, `default.htm`).

---

### Fixed
1. **Request Handling Issues**:
   - Fixed an error where the server could return a 500 error due to incorrect PHP request handling.
   - Resolved issues with incorrect MIME type determination for static files.

2. **Blocking Suspicious Requests**:
   - Fixed the logic for blocking requests containing potentially dangerous patterns (e.g., `.env`, `/shell`).

3. **OS Signal Handling**:
   - Fixed handling of `SIGHUP`, `SIGTERM`, and other signals for proper server reload and shutdown.

---

### Removed
1. **Deprecated Methods**:
   - Removed unused methods, such as `updateConfig` from the `VirtualHost` structure.

2. **Unused Configurations**:
   - Cleaned up outdated or unused configuration parameters to simplify the codebase.

---

### Security
1. **Protection Against Attacks**:
   - Added mechanisms to protect against SQL injections and XSS attacks.
   - Implemented blocking of suspicious requests via middleware.

2. **Minimum TLS Version**:
   - Set a restriction to use TLS version 1.2 and above for secure connections.

3. **IP Address Tracking**:
   - Implemented IP address tracking to prevent DDoS attacks.

---

### Documentation
1. **Code Comments**:
   - Added detailed comments for all key functions and methods.

2. **Configuration Guide**:
   - Updated the server setup guide to include new parameters and functionality.
