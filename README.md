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
   - All configurations are now managed through the database (`MySQL`) instead of static configuration files.
   - Virtual hosts, SSL certificates, and redirection rules are stored in the database for easy management.

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

### 2. **Set Up MySQL Database**
   GubinNET uses MySQL as its database backend to store configuration data. Follow these steps to set up MySQL:

   #### a. **Install MySQL**
   - Install MySQL on your server or local machine:
     ```bash
     sudo apt update
     sudo apt install mysql-server
     ```
   - Secure your MySQL installation:
     ```bash
     sudo mysql_secure_installation
     ```

   #### b. **Create a Database and User**
   - Log in to MySQL:
     ```bash
     sudo mysql -u root -p
     ```
   - Create a database named `gubinnet`:
     ```sql
     CREATE DATABASE gubinnet;
     ```
   - Create a user and grant privileges:
     ```sql
     CREATE USER 'gubinnet_user'@'localhost' IDENTIFIED BY 'your_password';
     GRANT ALL PRIVILEGES ON gubinnet.* TO 'gubinnet_user'@'localhost';
     FLUSH PRIVILEGES;
     EXIT;
     ```

   #### c. **Import Default Data**
   - Use the provided `default.sql` file to populate the database with initial settings:
     ```bash
     mysql -u gubinnet_user -p gubinnet < default.sql
     ```
   - This file contains the schema and test data for virtual hosts, SSL certificates, and redirection rules.

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

### 4. **Add Your Files**
   - Place your website or application files in the designated folder. For example:
     ```
     /var/www/my-site
     ```

## **Key Features in the Code**

### 1. **Database-Driven Configuration**
   - Virtual hosts, SSL certificates, and redirection rules are stored in the `virtual_hosts` table in MySQL.
   - Example query to add a new virtual host:
     ```sql
     INSERT INTO virtual_hosts (
         server_name, listen_port, root_path, index_file, try_files, use_ssl, 
         cert_path, key_path, redirect_to_https
     ) VALUES (
         'example.com', 80, '/var/www/example', 'index.html', '$uri /index.html', FALSE, NULL, NULL, TRUE
     );
     ```

### 2. **AntiDDoS Protection**
   - The `AntiDDoS` module limits the number of requests per second from a single IP address.
   - If the limit is exceeded, the IP is blocked for a configurable duration.

### 3. **HTTPS Support with SNI**
   - The server supports multiple SSL certificates using Server Name Indication (SNI).
   - Certificates are dynamically loaded from the database based on the requested hostname.

### 4. **Graceful Shutdown and Reload**
   - The server listens for system signals (`SIGTERM`, `SIGHUP`) to gracefully shut down or reload configurations.

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
- **`default.sql`**: This file is included in the repository and contains the initial database schema and test data. Use it to set up your MySQL database during the first installation.
- **Database Connection String**: Update the MySQL connection string in the `main.go` file to match your database credentials:
  ```go
  dbConnectionString := "user:password@tcp(127.0.0.1:3306)/gubinnet"
  ```
