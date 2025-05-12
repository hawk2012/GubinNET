# GubinNET AppMode Configuration

GubinNET supports multiple application modes (`AppMode`) to handle requests dynamically based on the type of application or service being hosted. The `AppMode` is defined in `.ini` configuration files for each virtual host and determines how incoming requests are processed.

## Supported AppModes

### 1. **dotnet**
   - **Purpose**: Used to run ASP.NET Core applications.
   - **Required Parameters**:
     - `dll_path`: Path to the compiled `.dll` file of the application.
     - `internal_port`: Internal port on which the application runs.
   - **Environment Variables**:
     - `ASPNETCORE_URLS=http://0.0.0.0:{internal_port}`
     - `ASPNETCORE_ENVIRONMENT=Production`
     - `DOTNET_PRINT_TELEMETRY_MESSAGE=false`
     - `ASPNETCORE_SERVER_HEADER=`
   - **Behavior**:
     - Requests are proxied to the internal port where the .NET application is running.
     - The server ensures the application is started and monitored.

---

### 2. **nodejs**
   - **Purpose**: Used to run Node.js applications.
   - **Required Parameters**:
     - `script_path`: Path to the main JavaScript file of the application.
     - `internal_port`: Internal port on which the application listens.
   - **Environment Variables**:
     - `PORT={internal_port}`
     - `NODE_ENV=production`
   - **Behavior**:
     - Requests are proxied to the internal port where the Node.js application is running.
     - The server ensures the application is started and monitored.

---

### 3. **Proxy Mode**
   - **Purpose**: Proxies requests to an external backend server.
   - **Required Parameter**:
     - `proxy_url`: URL of the backend server to which requests should be proxied.
   - **Behavior**:
     - All incoming requests are forwarded to the specified backend URL.
     - Useful for load balancing or integrating with external services.

---

### 4. **Static File Server**
   - **Purpose**: Serves static files (HTML, CSS, JS, etc.) directly from a specified directory.
   - **Required Parameters**:
     - `root_path`: Directory containing the static files.
     - `try_files`: Fallback file for Single Page Applications (e.g., `index.html`).
   - **Behavior**:
     - Files are served directly from the `root_path`.
     - If `try_files` is specified, unmatched routes serve the fallback file (useful for SPAs like React or Angular).

## Example Configurations

### .NET Application
```ini
server_name=example.com
listen_port=80
root_path=/var/www/example
app_mode=dotnet
dll_path=/var/www/example/app.dll
internal_port=5000
use_ssl=true
cert_path=/etc/ssl/certs/example.com.crt
key_path=/etc/ssl/private/example.com.key
redirect_to_https=true
```

### Node.js Application
```ini
server_name=example.com
listen_port=80
root_path=/var/www/example
app_mode=nodejs
script_path=/var/www/example/app.js
internal_port=3000
use_ssl=true
cert_path=/etc/ssl/certs/example.com.crt
key_path=/etc/ssl/private/example.com.key
redirect_to_https=true
```

### Proxy Server
```ini
server_name=example.com
listen_port=80
root_path=
proxy_url=http://backend-server/
use_ssl=true
cert_path=/etc/ssl/certs/example.com.crt
key_path=/etc/ssl/private/example.com.key
redirect_to_https=true
```

### Static File Server
```ini
server_name=example.com
listen_port=80
root_path=/var/www/html
try_files=index.html
use_ssl=true
cert_path=/etc/ssl/certs/example.com.crt
key_path=/etc/ssl/private/example.com.key
redirect_to_https=true
```

## Key Features

- **Dynamic Process Management**:
  - For `dotnet` and `nodejs` modes, the server automatically starts the application if it is not already running.
  - Ensures graceful shutdown of applications when the server stops.

- **SSL/TLS Support**:
  - SSL certificates can be configured for secure connections in all modes.

- **Fallback Mechanism**:
  - For static file servers hosting SPAs, the `try_files` parameter ensures unmatched routes serve the correct file (e.g., `index.html`).

- **Monitoring and Logging**:
  - Requests and application states are logged for debugging and monitoring purposes.
  - Prometheus metrics provide insights into request handling and application performance.

## Important Notes

1. **Internal Ports**:
   - For `dotnet` and `nodejs` applications, it is recommended to use internal ports outside the standard HTTP/HTTPS range (e.g., `5000`, `3000`).

2. **Security**:
   - Always configure SSL certificates for secure communication, especially for production environments.

3. **Configuration Files**:
   - All configurations are currently stored in `.ini` files located in `/etc/gubinnet/config`.
   - Use the `SIGHUP` signal to reload configurations dynamically without restarting the server.

4. **Future Work**:
   - Migration to a MySQL database backend for centralized configuration management is planned.
