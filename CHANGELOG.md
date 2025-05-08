Here is the rewritten **Changelog** for the GubinNET project, organized and formatted for clarity while maintaining all key details:

---

# Changelog

All notable changes to the GubinNET project will be documented in this file.

---

## [1.5.1] - 2025-06-05

### Added
- **AntiDDoS Integration**: Introduced AntiDDoS middleware to protect against excessive requests. Configurable limits and block durations are supported.
- **Prometheus Metrics**: Integrated Prometheus metrics for monitoring HTTP request counts, durations, and active connections.
- **Graceful Shutdown**: Implemented graceful shutdown mechanisms for both HTTP and HTTPS servers to ensure smooth termination.
- **SNI Support**: Enabled SNI (Server Name Indication) for dynamically serving multiple SSL certificates based on hostnames.
- **Caching Mechanism**: Added an in-memory caching system for static files to improve performance and reduce disk I/O.
- **Configuration Reloading**: Added support for reloading configuration files on-the-fly using the `SIGHUP` signal.
- **Proxy Support**: Implemented reverse proxy functionality for virtual hosts with a `proxy_url` configuration option.
- **Security Middleware**: Enhanced security by blocking suspicious request patterns such as `.env`, `/shell`, and other common attack vectors.

### Changed
- **Logger Enhancements**: Updated the logger to support JSONB format with optional gzip compression for log files.
- **Middleware Refactoring**: Reorganized the middleware stack to include metrics, logging, and security layers in a clean and modular way.
- **Error Handling**: Improved error handling and reporting for invalid configurations, missing files, and server errors.
- **Virtual Host Management**: Simplified virtual host updates during configuration reloads by directly modifying fields instead of relying on deprecated methods like `updateConfig`.

### Fixed
- **Assignment Mismatch**: Resolved mismatch issues in variable assignments when initializing AntiDDoS configurations.
- **Argument Count Errors**: Fixed argument count mismatches in calls to `antiddos.NewAntiDDoS`.
- **Undefined Methods**: Removed usage of undefined methods such as `updateConfig` from the `VirtualHost` structure.
- **Static File Serving**: Corrected issues with serving index files (`index.html`, `index.htm`) in directories.
- **ETag and Last-Modified Headers**: Ensured proper handling of `ETag` and `Last-Modified` headers for cached responses to prevent unnecessary re-fetching.

### Removed
- **Unused Methods**: Removed unused or redundant methods such as `updateConfig` from the `VirtualHost` structure.
- **Deprecated Configurations**: Cleaned up deprecated or unused configuration parameters to streamline the codebase.

### Security
- **Blocked Patterns**: Added common attack patterns (e.g., `.env`, `/shell`) to the security middleware to prevent unauthorized access attempts.
- **TLS Configuration**: Enforced a minimum TLS version of 1.2 for secure connections.
- **IP Tracking**: Implemented IP-based request tracking and blocking to mitigate DDoS attacks effectively.

### Documentation
- **Code Comments**: Added detailed inline comments throughout the codebase for better readability and maintainability.
- **Configuration Guide**: Updated documentation to include new configuration options and their usage, ensuring users can easily understand and configure the server.
