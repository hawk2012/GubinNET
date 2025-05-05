-- Создание базы данных
CREATE DATABASE IF NOT EXISTS gubinnet;
USE gubinnet;

-- Таблица основных настроек
CREATE TABLE server_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(255) NOT NULL UNIQUE,
    setting_value TEXT NOT NULL
);

-- Таблица виртуальных хостов
CREATE TABLE virtual_hosts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    server_name VARCHAR(255) NOT NULL,
    listen_port INT NOT NULL,
    root_path VARCHAR(255) NOT NULL,
    index_file VARCHAR(255),
    try_files TEXT,
    use_ssl BOOLEAN NOT NULL DEFAULT FALSE,
    cert_path VARCHAR(255),
    key_path VARCHAR(255),
    redirect_to_https BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE unique_server_port (server_name, listen_port)
);

-- Вставка тестовых данных в server_settings
INSERT INTO server_settings (setting_key, setting_value) VALUES
('worker_processes', 'auto'),
('error_log', '/var/log/gubinnet/error.log'),
('pid', '/var/run/gubinnet.pid'),
('gzip_enabled', 'true'),
('gzip_min_length', '1024'),
('gzip_comp_level', '6'),
('max_request_size', '10485760'), -- 10MB
('keepalive_timeout', '65');

-- Вставка тестовых данных в virtual_hosts
INSERT INTO virtual_hosts (
    server_name, listen_port, root_path, index_file, try_files, use_ssl, 
    cert_path, key_path, redirect_to_https
) VALUES
-- HTTP-запись (без SSL)
('example.com', 80, '/var/www/example', 'index.html', '$uri /index.html', FALSE, NULL, NULL, TRUE),

-- HTTPS-запись (с SSL)
('secure.example.com', 443, '/var/www/secure', 'index.html', '$uri /index.html', TRUE, 
'/etc/ssl/certs/secure_example_com.crt', '/etc/ssl/private/secure_example_com.key', TRUE),

-- Запись без редиректа на HTTPS
('no-redirect.example.com', 80, '/var/www/no-redirect', 'index.html', '$uri /index.html', FALSE, NULL, NULL, FALSE),

-- Запись для WordPress
('wordpress.example.com', 80, '/var/www/wordpress', 'index.php', NULL, FALSE, NULL, NULL, TRUE),

-- Запись для SPA (Single Page Application)
('spa.example.com', 80, '/var/www/spa', 'index.html', '$uri /index.html', FALSE, NULL, NULL, TRUE);