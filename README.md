# **GubinNET Technical Documentation**

GubinNET is a modern, lightweight, and extensible web server designed for developers, system administrators, and businesses to deploy and manage websites, APIs, and web applications efficiently. Below is a detailed technical overview of its features, architecture, and functionality.

---

## **1. Core Features**

### **1.1 Flexible Configuration**
- **INI-Based Configuration Files**: All server settings are managed through INI-like configuration files stored in `/etc/gubinnet/config`. Each virtual host has its own `.ini` file, allowing for granular control over settings such as:
  - Server name (`server_name`)
  - Listening port (`listen_port`)
  - Root directory (`root_path`)
  - Index file (`index_file`)
  - SSL/TLS support (`use_ssl`, `cert_path`, `key_path`)
  - Redirection rules (`redirect_to_https`)
  - Proxy URLs (`proxy_url`)
- **Dynamic Reloading**: Configurations can be reloaded without restarting the server by sending the `SIGHUP` signal. This ensures minimal downtime during updates.

### **1.2 Virtual Host Management**
- **Multiple Virtual Hosts**: GubinNET supports hosting multiple websites or applications on the same server. Each virtual host can have its own configuration, including separate root directories, SSL certificates, and proxy settings.
- **Dynamic Host Addition/Removal**: New virtual hosts can be added or removed dynamically by updating the configuration files and reloading the server.

### **1.3 Security Features**
- **AntiDDoS Protection**:
  - Limits the number of requests per second from a single IP address.
  - Blocks malicious IPs after exceeding the request threshold.
  - Logs suspicious activity for further analysis.
- **SSL/TLS Support with SNI**:
  - Supports multiple SSL certificates using Server Name Indication (SNI).
  - Dynamically loads certificates based on the requested hostname.
- **Security Middleware**:
  - Blocks suspicious requests targeting sensitive endpoints (e.g., `.env`, `/shell`, `/wordpress/wp-admin/setup-config.php`).
  - Prevents unauthorized access to critical resources.

### **1.4 Performance Optimization**
- **Caching**:
  - Files are cached in memory to reduce disk I/O and improve response times.
  - Cache entries include metadata such as modification time, size, and content type.
- **Content Compression**:
  - Responses are compressed using Gzip if the client supports it (`Accept-Encoding: gzip`).
- **Request Metrics**:
  - Tracks active connections, request durations, and total HTTP requests using Prometheus metrics.

### **1.5 Monitoring and Diagnostics**
- **Prometheus Metrics**:
  - Exposes metrics for monitoring server performance:
    - Total HTTP requests (`http_requests_total`)
    - Request durations (`http_request_duration_seconds`)
    - Active connections (`http_active_connections`)
  - Metrics can be scraped by Prometheus for visualization in tools like Grafana.
- **Structured Logging**:
  - Logs are recorded in JSON format for easy analysis.
  - Includes details such as request ID, method, path, status code, duration, and user agent.

### **1.6 Graceful Shutdown and Reliability**
- **Graceful Shutdown**:
  - Active connections are given a grace period (30 seconds) to complete before shutting down.
  - Ensures no data loss or abrupt termination during maintenance.
- **High Availability**:
  - Designed to handle high loads with stability and reliability.

---

## **2. Advanced Features**

### **2.1 Custom Error Pages**
- Provides user-friendly error pages for common HTTP errors (e.g., 404 Not Found, 500 Internal Server Error).
- Includes details such as the request ID for easier debugging.

### **2.2 PHP Support**
- Supports PHP applications using the `php-cgi` binary.
- To enable PHP support, install `php-cgi`:
  ```bash
  sudo apt install php-cgi
  ```

### **2.3 Middleware Stack**
- **Security Middleware**:
  - Blocks suspicious requests targeting sensitive endpoints.
- **AntiDDoS Middleware**:
  - Limits requests per second and blocks malicious IPs.
- **Logging Middleware**:
  - Logs every request with details such as method, path, status code, duration, and request ID.
- **Metrics Middleware**:
  - Tracks active connections and updates Prometheus metrics.

### **2.4 File Serving and Fallback Routes**
- **Static File Serving**:
  - Efficiently serves static files (HTML, CSS, JavaScript, images, etc.) with caching and compression.
- **Fallback Routes**:
  - Supports fallback routes for single-page applications (SPAs) like React, Angular, or Vue.js.
  - Allows specifying custom fallback files using the `try_files` directive.

### **2.5 Proxy Support**
- Forwards requests to backend services using the `proxy_url` directive.
- Useful for microservices, APIs, and load balancing scenarios.

---

## **3. Architecture Overview**

### **3.1 Configuration Parser**
- Parses INI-like configuration files to load virtual host settings.
- Validates the existence of root directories and logs warnings for missing paths.

### **3.2 Virtual Host Management**
- Manages multiple virtual hosts with independent configurations.
- Dynamically starts or stops virtual hosts based on configuration changes.

### **3.3 Middleware Pipeline**
- Implements a middleware stack to enhance functionality:
  - Security checks
  - AntiDDoS protection
  - Logging and metrics collection

### **3.4 HTTPS Server with SNI**
- Starts an HTTPS server on port 443 with support for multiple SSL certificates.
- Dynamically loads certificates based on the requested hostname.

### **3.5 HTTP Server**
- Starts an HTTP server on port 80.
- Redirects traffic to HTTPS if `redirect_to_https` is enabled.

---

## **4. Deployment and Usage**

### **4.1 Installation**
- Ensure Go is installed:
  ```bash
  go version
  ```
- Clone the repository:
  ```bash
  git clone https://github.com/hawk2012/GubinNET.git
  cd GubinNET
  ```
- Build the server:
  ```bash
  go build -o gubinnet
  ```

### **4.2 Configuration Setup**
- Create the configuration and logs directories:
  ```bash
  sudo mkdir -p /etc/gubinnet/{config,logs}
  ```
- Add virtual host configurations in `/etc/gubinnet/config`. Example (`example.com.ini`):
  ```ini
  server_name=example.com
  listen_port=80
  root_path=/var/www/example
  index_file=index.html
  try_files=$uri /index.html
  use_ssl=false
  cert_path=
  key_path=
  redirect_to_https=true
  proxy_url=
  ```

### **4.3 Running the Server**
- Start the server:
  ```bash
  ./gubinnet
  ```
- Reload configurations without restarting:
  ```bash
  kill -SIGHUP <server-pid>
  ```

---

## **5. Use Cases**

### **5.1 Personal Websites and Blogs**
- Ideal for hosting personal websites, portfolios, or blogs with minimal configuration.

### **5.2 Web Applications**
- Supports applications built with Node.js, .NET, PHP, and other frameworks.

### **5.3 APIs and Microservices**
- Provides routing and proxying capabilities for API-based architectures.

### **5.4 Single-Page Applications (SPAs)**
- Handles fallback routes for SPAs like React, Angular, or Vue.js.

---

## **6. Why Choose GubinNET?**

- **Ease of Use**: Simple INI-based configuration and out-of-the-box functionality.
- **Performance**: Optimized for fast and efficient file serving with caching and compression.
- **Security**: Built-in AntiDDoS protection, SSL/TLS support, and security middleware.
- **Flexibility**: Supports multiple technologies, virtual hosts, and dynamic configurations.
- **Monitoring**: Integrated Prometheus metrics and structured logging for real-time insights.

---

## **7. Support and Help**

For questions or issues, contact the GubinNET team:
- Official Repository: [GitHub](https://github.com/hawk2012/GubinNET)
- Email: platform@gubin.systems

**Thank you for choosing GubinNET!**  
We hope this server becomes your reliable assistant in the world of web development. Try it today and experience its simplicity and power! 😊
