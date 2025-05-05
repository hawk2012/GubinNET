# Changelog

## [1.5] - 2025-05-05

### Overview
This release marks a significant improvement in the architecture of GubinNET. The server has been refactored to enhance flexibility, scalability, and ease of management for hosting multiple virtual hosts and configurations.

### Key Changes

#### 1. **Static INI Configuration Files**
   - **Purpose**: To manage virtual host configurations in a simple and structured format.
   - **Details**:
     - Virtual hosts are defined in `.ini` files located in `/etc/gubinnet/config`.
     - Each file contains key-value pairs for settings such as `server_name`, `listen_port`, `root_path`, and `use_ssl`.
     - Configurations can be reloaded dynamically using the `SIGHUP` signal without restarting the server.
   - **Benefits**:
     - Simplified management of multiple virtual hosts.
     - Real-time updates to configurations without downtime.

#### 2. **Dynamic SSL Certificate Loading with SNI**
   - **Purpose**: To support multiple SSL certificates for different domains on the same server.
   - **Details**:
     - Implemented Server Name Indication (SNI) to dynamically load SSL certificates based on the requested hostname.
     - Certificates and private keys are stored in the `cert_path` and `key_path` fields of the `.ini` configuration files.
     - HTTPS server listens on port 443 and uses the `GetCertificate` function to fetch the appropriate certificate for each request.
   - **Benefits**:
     - Enhanced security with domain-specific SSL certificates.
     - Simplified management of SSL configurations.

#### 3. **Automatic HTTP → HTTPS Redirection**
   - **Purpose**: To enforce secure connections for configured domains.
   - **Details**:
     - Added a `redirect_to_https` flag in the `.ini` configuration files to enable or disable automatic redirection from HTTP to HTTPS.
     - Requests to HTTP are redirected to HTTPS if the `redirect_to_https` flag is set to `TRUE`.
   - **Benefits**:
     - Improved security by ensuring all traffic is encrypted.
     - Simplified enforcement of HTTPS policies.

#### 4. **Enhanced Security Middleware**
   - **Purpose**: To protect against malicious requests and common vulnerabilities.
   - **Details**:
     - Added middleware to block suspicious patterns such as `.env`, `/shell`, and `/wordpress/wp-admin/setup-config.php`.
     - Logs blocked requests with detailed information, including IP addresses and paths.
   - **Benefits**:
     - Reduced risk of unauthorized access and attacks.
     - Improved logging for security audits.

#### 5. **Improved Caching Mechanism**
   - **Purpose**: To optimize performance for static files.
   - **Details**:
     - Implemented an in-memory cache (`cacheEntry`) to store file content, modification times, and metadata.
     - Cache invalidation occurs when file modifications are detected on disk.
   - **Benefits**:
     - Faster response times for frequently accessed files.
     - Reduced disk I/O overhead.

#### 6. **Anti-DDoS Protection**
   - **Purpose**: To mitigate DDoS attacks and prevent abuse.
   - **Details**:
     - Integrated the `AntiDDoS` module to limit the number of requests per second from a single IP address.
     - Configurable parameters include `MaxRequestsPerSecond` and `BlockDuration`.
   - **Benefits**:
     - Reduced risk of server overload during high-traffic scenarios.
     - Improved stability and availability.

#### 7. **Prometheus Metrics**
   - **Purpose**: To provide insights into server performance and usage.
   - **Details**:
     - Added Prometheus metrics for tracking HTTP requests, active connections, and request durations.
     - Metrics are exposed via the `/metrics` endpoint for integration with monitoring tools.
   - **Benefits**:
     - Enhanced observability for server health and performance.
     - Simplified debugging and capacity planning.

#### 8. **Error Handling and Logging**
   - **Purpose**: To improve user experience and simplify troubleshooting.
   - **Details**:
     - Added custom error pages for HTTP errors (e.g., 403, 404, 500).
     - Enhanced logging with unique request IDs, timestamps, and detailed metadata.
   - **Benefits**:
     - Improved clarity for end-users encountering errors.
     - Simplified debugging for administrators.

#### 9. **SPA Fallback Support**
   - **Purpose**: To handle routing for Single Page Applications (SPAs).
   - **Details**:
     - Added logic to serve `index.html` for unmatched routes in SPAs.
     - Supports frameworks like React, Angular, and Vue.js.
   - **Benefits**:
     - Seamless integration with modern frontend frameworks.

---

### Known Issues

- High traffic loads may cause delays if Anti-DDoS parameters are not optimally configured.
- Missing or incorrect SSL certificates in the `.ini` files may result in HTTPS failures.

### Future Work

- Migrate configuration management from `.ini` files to a MySQL database backend.
- Add WebSocket support using the Gorilla WebSocket library.
- Implement HTTP/3 and QUIC protocols for improved performance.
- Enhance security features, such as rate limiting for specific endpoints.