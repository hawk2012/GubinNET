package config

import "time"

type ServerConfig struct {
	Addr         string        `yaml:"addr"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`
}

type AntiDDoSConfig struct {
	MaxRequestsPerSecond int           `yaml:"max_requests_per_second"`
	BlockDuration        time.Duration `yaml:"block_duration"`
	LogFilePath          string        `yaml:"log_file_path"`
}

type VirtualHost struct {
	ServerName      string   `yaml:"server_name"`
	ListenPort      int      `yaml:"listen_port"`
	Root            string   `yaml:"root"`
	Index           string   `yaml:"index"`
	TryFiles        []string `yaml:"try_files"`
	UseSSL          bool     `yaml:"use_ssl"`
	CertPath        string   `yaml:"cert_path"`
	KeyPath         string   `yaml:"key_path"`
	RedirectToHTTPS bool     `yaml:"redirect_to_https"`
	ProxyURL        string   `yaml:"proxy_url"`
}

type Config struct {
	Server       *ServerConfig           `yaml:"server"`
	AntiDDoS     *AntiDDoSConfig         `yaml:"antiddos"`
	VirtualHosts map[string]*VirtualHost `yaml:"virtual_hosts"`
}
