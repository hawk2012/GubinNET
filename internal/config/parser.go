package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func Load(configDir string) (*Config, error) {
	config := &Config{
		Server: &ServerConfig{
			Addr:         ":80",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		AntiDDoS: &AntiDDoSConfig{
			MaxRequestsPerSecond: 100,
			BlockDuration:        60 * time.Second,
			LogFilePath:          "/etc/gubinnet/logs/antiddos.log",
		},
		VirtualHosts: make(map[string]*VirtualHost),
	}

	files, err := os.ReadDir(configDir)
	if err != nil {
		return nil, fmt.Errorf("read config directory: %w", err)
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".conf") {
			host, err := parseVirtualHost(filepath.Join(configDir, file.Name()))
			if err != nil {
				return nil, fmt.Errorf("parse virtual host %s: %w", file.Name(), err)
			}
			config.VirtualHosts[host.ServerName] = host
		}
	}

	return config, nil
}

func parseVirtualHost(filePath string) (*VirtualHost, error) {
	host := &VirtualHost{
		ListenPort: 80,
		Index:      "index.html",
		TryFiles:   []string{"$uri", "$uri/", "$uri.html"},
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch key {
		case "server_name":
			host.ServerName = value
		case "listen_port":
			if port, err := strconv.Atoi(value); err == nil {
				host.ListenPort = port
			}
		case "root_path":
			host.Root = value
		case "index_file":
			host.Index = value
		case "try_files":
			host.TryFiles = strings.Split(value, " ")
		case "use_ssl":
			host.UseSSL = value == "true"
		case "cert_path":
			host.CertPath = value
		case "key_path":
			host.KeyPath = value
		case "redirect_to_https":
			host.RedirectToHTTPS = value == "true"
		case "proxy_url":
			host.ProxyURL = value
		}
	}

	if host.ServerName == "" {
		return nil, fmt.Errorf("server_name is required")
	}

	return host, nil
}
