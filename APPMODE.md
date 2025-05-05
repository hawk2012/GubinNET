# GubinNET AppMode Configuration

GubinNET supports multiple application modes (`AppMode`) to handle requests dynamically based on the type of application or service being hosted. The `AppMode` is defined in the MySQL database for each virtual host and determines how incoming requests are processed.

## Supported AppModes

### 1. **dotnet**
   - **Purpose**: Used to run ASP.NET Core applications.
   - **Required Parameters**:
     - `DllPath`: Path to the compiled `.dll` file of the application.
     - `InternalPort`: Internal port on which the application runs.
   - **Environment Variables**:
     - `ASPNETCORE_URLS=http://0.0.0.0:{InternalPort}`
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
     - `ScriptPath`: Path to the main JavaScript file of the application.
     - `InternalPort`: Internal port on which the application listens.
   - **Environment Variables**:
     - `PORT={InternalPort}`
     - `NODE_ENV=production`
   - **Behavior**:
     - Requests are proxied to the internal port where the Node.js application is running.
     - The server ensures the application is started and monitored.

---

### 3. **Proxy Mode**
   - **Purpose**: Proxies requests to an external backend server.
   - **Required Parameter**:
     - `DefaultProxy`: URL of the backend server to which requests should be proxied.
   - **Behavior**:
     - All incoming requests are forwarded to the specified backend URL.
     - Useful for load balancing or integrating with external services.

---

### 4. **Static File Server**
   - **Purpose**: Serves static files (HTML, CSS, JS, etc.) directly from a specified directory.
   - **Required Parameters**:
     - `WebRootPath`: Directory containing the static files.
     - `SPAFallback`: Fallback file for Single Page Applications (e.g., `index.html`).
   - **Behavior**:
     - Files are served directly from the `WebRootPath`.
     - If `SPAFallback` is specified, unmatched routes serve the fallback file (useful for SPAs like React or Angular).

## Example Configurations in MySQL

### .NET Application
```sql
INSERT INTO virtual_hosts (
    server_name, listen_port, root_path, app_mode, dll_path, internal_port, use_ssl, 
    cert_path, key_path, redirect_to_https
) VALUES (
    'example.com', 80, '/var/www/example', 'dotnet', '/var/www/example/app.dll', 5000, TRUE, 
    '/etc/ssl/certs/example.com.crt', '/etc/ssl/private/example.com.key', TRUE
);
```

### Node.js Application
```sql
INSERT INTO virtual_hosts (
    server_name, listen_port, root_path, app_mode, script_path, internal_port, use_ssl, 
    cert_path, key_path, redirect_to_https
) VALUES (
    'example.com', 80, '/var/www/example', 'nodejs', '/var/www/example/app.js', 3000, TRUE, 
    '/etc/ssl/certs/example.com.crt', '/etc/ssl/private/example.com.key', TRUE
);
```

### Proxy Server
```sql
INSERT INTO virtual_hosts (
    server_name, listen_port, root_path, default_proxy, use_ssl, 
    cert_path, key_path, redirect_to_https
) VALUES (
    'example.com', 80, '', 'http://backend-server/', TRUE, 
    '/etc/ssl/certs/example.com.crt', '/etc/ssl/private/example.com.key', TRUE
);
```

### Static File Server
```sql
INSERT INTO virtual_hosts (
    server_name, listen_port, root_path, spa_fallback, use_ssl, 
    cert_path, key_path, redirect_to_https
) VALUES (
    'example.com', 80, '/var/www/html', 'index.html', TRUE, 
    '/etc/ssl/certs/example.com.crt', '/etc/ssl/private/example.com.key', TRUE
);
```

## Key Features

- **Dynamic Process Management**:
  - For `dotnet` and `nodejs` modes, the server automatically starts the application if it is not already running.
  - Ensures graceful shutdown of applications when the server stops.

- **SSL/TLS Support**:
  - SSL certificates can be configured for secure connections in all modes.

- **Fallback Mechanism**:
  - For static file servers hosting SPAs, the `SPAFallback` parameter ensures unmatched routes serve the correct file (e.g., `index.html`).

- **Monitoring and Logging**:
  - Requests and application states are logged for debugging and monitoring purposes.
  - Prometheus metrics provide insights into request handling and application performance.

## Important Notes

1. **Internal Ports**:
   - For `dotnet` and `nodejs` applications, it is recommended to use internal ports outside the standard HTTP/HTTPS range (e.g., `5000`, `3000`).

2. **Security**:
   - Always configure SSL certificates for secure communication, especially for production environments.

3. **Database Configuration**:
   - All configurations are stored in the `virtual_hosts` table in the MySQL database.
   - Use the `SIGHUP` signal to reload configurations dynamically without restarting the server.

4. **Error Handling**:
   - If an application fails to start or crashes, the server logs detailed error messages for troubleshooting.
