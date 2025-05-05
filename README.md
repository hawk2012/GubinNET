# **GubinNET: A Simple and Powerful Web Server for Your Projects**

GubinNET is a modern web server designed to simplify the deployment and management of websites, applications, and APIs. It is ideal for developers, website owners, and even beginners who want to quickly launch their projects online.

## **What Can GubinNET Do?**

### 1. **Launch Websites and Applications with Ease**
   - Want to deploy a website or web application? Simply copy your project files into the server directory, and GubinNET will handle the rest.
   - Supports popular technologies: .NET, Node.js, PHP, and static sites (HTML, CSS, JavaScript).

### 2. **Protection Against Malicious Activity**
   - The server automatically protects your site from DDoS attacks and other threats using the `AntiDDoS` module.
   - Built-in security tools, such as SSL/TLS support and basic authentication, ensure your data remains secure.

### 3. **Fast and Efficient Performance**
   - GubinNET optimizes file handling and caches content for faster page loading.
   - Support for data compression (Gzip) ensures efficient file transfer.

### 4. **Flexible Configuration**
   - All configurations are managed through INI-like files located in `/etc/gubinnet/config`.
   - Virtual hosts, SSL certificates, and redirection rules are defined in separate `.ini` files for easy management.

### 5. **Monitoring and Diagnostics**
   - Built-in Prometheus metrics provide insights into server performance, including request counts, durations, and active connections.
   - Logs are recorded in an easy-to-read format, making it simple to analyze events.

## **What Can You Use GubinNET For?**

### 1. **Personal Websites and Blogs**
   - If you want to create a blog, portfolio, or personal homepage, GubinNET makes it quick and easy.

### 2. **Web Applications**
   - Developing an application using Node.js, .NET, or PHP? GubinNET automatically launches and manages your applications.

### 3. **APIs and Microservices**
   - Need a server for API operations? GubinNET supports request routing and proxying, making it perfect for microservice architectures.

### 4. **Dynamic Content Websites**
   - GubinNET excels at handling single-page applications (SPAs) like React, Angular, or Vue.js, thanks to its support for fallback routes.

---

## **How to Get Started?**

### 1. **Install GubinNET**
   - Download and install the server on your computer or hosting environment. Ensure you have Go installed:
     ```bash
     go version
     ```

### 2. **Set Up Configuration Directory**
   GubinNET uses INI-like configuration files stored in `/etc/gubinnet/config`. Follow these steps to set up the configuration:

   #### a. **Create Configuration Directory**
   - Create the configuration and logs directories:
     ```bash
     sudo mkdir -p /etc/gubinnet/{config,logs}
     ```

   #### b. **Add Virtual Host Configuration**
   - Create an INI file for each virtual host in `/etc/gubinnet/config`. Example (`example.com.ini`):
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

   #### c. **Verify Root Path**
   - Ensure the `root_path` exists and contains your website or application files:
     ```bash
     sudo mkdir -p /var/www/example
     sudo cp -r your-files/* /var/www/example/
     ```

### 3. **Build and Run the Server**
   - Clone the repository and navigate to the project directory:
     ```bash
     git clone https://github.com/hawk2012/GubinNET.git
     cd GubinNET
     ```
   - Build the server:
     ```bash
     go build -o gubinnet
     ```
   - Run the server:
     ```bash
     ./gubinnet
     ```

### 4. **Reload Configurations**
   - To reload configurations without restarting the server, send the `SIGHUP` signal:
     ```bash
     kill -SIGHUP <server-pid>
     ```

## **Key Features in the Code**

### 1. **INI-Based Configuration**
   - Virtual hosts, SSL certificates, and redirection rules are stored in INI-like files in `/etc/gubinnet/config`.
   - Example configuration (`example.com.ini`):
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

### 2. **AntiDDoS Protection**
   - The `AntiDDoS` module limits the number of requests per second from a single IP address.
   - If the limit is exceeded, the IP is blocked for a configurable duration.

### 3. **HTTPS Support with SNI**
   - The server supports multiple SSL certificates using Server Name Indication (SNI).
   - Certificates are dynamically loaded from the filesystem based on the requested hostname.

### 4. **Graceful Shutdown and Reload**
   - The server listens for system signals (`SIGTERM`, `SIGHUP`) to gracefully shut down or reload configurations.

### 5. **Custom Error Pages**
   - GubinNET serves user-friendly error pages for common HTTP errors (e.g., 404 Not Found, 500 Internal Server Error). These pages include details such as the request ID for easier debugging.

### 6. **PHP Support**
   - GubinNET supports PHP applications using the `php-cgi` binary. To enable PHP support:
     ```bash
     sudo apt install php-cgi
     ```

### 7. **Prometheus Metrics**
   - GubinNET exposes metrics for monitoring using Prometheus. Metrics include:
     - Total HTTP requests
     - Request durations
     - Active connections

   To access metrics:
   1. Install Prometheus: [Prometheus Installation Guide](https://prometheus.io/docs/prometheus/latest/installation/)
   2. Configure Prometheus to scrape metrics from `http://<server-ip>:<metrics-port>/metrics`.
   3. Visualize metrics using Grafana or Prometheus's built-in dashboard.

## **Why Choose GubinNET?**

- **Ease of Use**: No complex configurations — everything works "out of the box."
- **Reliability**: The server performs stably even under high loads.
- **Security**: Protection against attacks and unauthorized access.
- **Flexibility**: Support for multiple technologies and extensibility through plugins.

## **Support and Help**

If you have any questions or issues, our team is always ready to assist:
- Official Repository: [GitHub](https://github.com/hawk2012/GubinNET)
- Email: platform@gubin.systems

**Thank you for choosing GubinNET!**  
We hope this server becomes your reliable assistant in the world of web development. Try it today and see for yourself how simple and convenient it is! 😊

---

### **Additional Notes**
- **Configuration Directory**: Ensure the `/etc/gubinnet/config` directory exists and contains valid `.ini` files for each virtual host.
- **Logs Directory**: Logs are stored in `/etc/gubinnet/logs` for easy analysis.
- **PHP-CGI**: Install `php-cgi` to enable PHP support:
  ```bash
  sudo apt install php-cgi
  ```