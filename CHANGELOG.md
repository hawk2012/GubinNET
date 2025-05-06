# Changelog

All notable changes to the GubinNET project will be documented in this file.

## [1.5.1] - 2025-06-05

### Added
- **AntiDDoS Integration**: Added AntiDDoS middleware for protection against excessive requests with configurable limits and block durations.
- **Prometheus Metrics**: Integrated Prometheus metrics for monitoring HTTP request counts, durations, and active connections.
- **Graceful Shutdown**: Implemented graceful shutdown mechanisms for both HTTP and HTTPS servers.
- **SNI Support**: Enabled SNI (Server Name Indication) support for serving multiple SSL certificates dynamically.
- **Caching Mechanism**: Introduced an in-memory caching system for static files to improve performance.
- **Configuration Reloading**: Added support for reloading configuration on-the-fly via `SIGHUP` signal.
- **Proxy Support**: Implemented reverse proxy capabilities for virtual hosts with a `proxy_url` configuration.
- **Security Middleware**: Enhanced security by blocking suspicious request patterns such as `.env`, `/shell`, and others.

### Changed
- **Logger Enhancements**: Updated logger to support JSONB format with optional gzip compression for log files.
- **Middleware Refactoring**: Reorganized middleware stack to include metrics, logging, and security layers.
- **Error Handling**: Improved error handling and reporting for invalid configurations, missing files, and server errors.
- **Virtual Host Management**: Simplified virtual host updates during configuration reloads by directly modifying fields instead of using `updateConfig`.

### Fixed
- **Assignment Mismatch**: Resolved mismatch in variable assignments when initializing AntiDDoS.
- **Argument Count Errors**: Fixed argument count mismatches in calls to `antiddos.NewAntiDDoS`.
- **Undefined Methods**: Removed usage of undefined methods like `updateConfig` from the `VirtualHost` structure.
- **Static File Serving**: Corrected issues with serving index files (`index.html`, `index.htm`) in directories.
- **ETag and Last-Modified Headers**: Ensured proper handling of `ETag` and `Last-Modified` headers for cached responses.

### Removed
- **Unused Methods**: Removed unused or redundant methods such as `updateConfig` from the `VirtualHost` structure.
- **Deprecated Configurations**: Cleaned up deprecated or unused configuration parameters.

### Security
- **Blocked Patterns**: Added common attack patterns to the security middleware to prevent unauthorized access.
- **TLS Configuration**: Enforced minimum TLS version 1.2 for secure connections.
- **IP Tracking**: Implemented IP-based request tracking and blocking for DDoS protection.

### Documentation
- **Code Comments**: Added detailed inline comments for better code readability and maintainability.
- **Configuration Guide**: Updated documentation to include new configuration options and their usage.

---

This release focuses on improving stability, security, and performance while ensuring seamless integration with modern monitoring tools like Prometheus. For more details, refer to the source code and documentation.