package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
)

// Config represents the configuration for GubinNET server
type Config struct {
	Port         string            `json:"port"`
	PublicDir    string            `json:"public_dir"`
	RewriteRules map[string]string `json:"rewrite_rules"`
	AntiDDoS     AntiDDoSConfig    `json:"antiddos"`
	AllowedBots  []string          `json:"allowed_bots"`
	BlockedIPs   []string          `json:"blocked_ips"`
	AllowedIPs   []string          `json:"allowed_ips"`
	MaxFileSize  int64             `json:"max_file_size"` // in bytes
	Timeout      int               `json:"timeout"`       // in seconds
}

// AntiDDoSConfig holds the configuration for anti-DDoS protection
type AntiDDoSConfig struct {
	Enabled          bool `json:"enabled"`
	MaxRequests      int  `json:"max_requests"`
	WindowSeconds    int  `json:"window_seconds"`
	BlockDuration    int  `json:"block_duration"`     // in minutes
	EnableCaptcha    bool `json:"enable_captcha"`
	ChallengeEnabled bool `json:"challenge_enabled"` // JavaScript challenge
}

// DefaultConfig returns a default configuration
func DefaultConfig() Config {
	return Config{
		Port:      "8080",
		PublicDir: "public",
		RewriteRules: map[string]string{
			"/api/(.*)":    "/internal/api/$1",
			"/blog/(.*)":   "/wp-content/$1",
			"/images/(.*)": "/assets/images/$1",
		},
		AntiDDoS: AntiDDoSConfig{
			Enabled:          true,
			MaxRequests:      100,
			WindowSeconds:    60,
			BlockDuration:    10,
			EnableCaptcha:    false,
			ChallengeEnabled: true,
		},
		AllowedBots: []string{
			"googlebot", "bingbot", "slurp", 
			"duckduckbot", "baiduspider", "yandex",
		},
		BlockedIPs:  []string{},
		AllowedIPs:  []string{},
		MaxFileSize: 10 * 1024 * 1024, // 10MB
		Timeout:     30,
	}
}

// LoadConfig loads the configuration from a JSON file
func LoadConfig(filename string) (Config, error) {
	var config Config

	// Try to read the config file
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Printf("Config file %s not found, using default config: %v", filename, err)
		return DefaultConfig(), nil
	}

	// Parse the JSON
	if err := json.Unmarshal(data, &config); err != nil {
		log.Printf("Error parsing config file: %v", err)
		return DefaultConfig(), nil
	}

	// Apply defaults for any missing fields
	defaultConfig := DefaultConfig()
	if config.Port == "" {
		config.Port = defaultConfig.Port
	}
	if config.PublicDir == "" {
		config.PublicDir = defaultConfig.PublicDir
	}
	if config.RewriteRules == nil {
		config.RewriteRules = defaultConfig.RewriteRules
	}
	if config.AntiDDoS.MaxRequests == 0 {
		config.AntiDDoS = defaultConfig.AntiDDoS
	}
	if config.AllowedBots == nil {
		config.AllowedBots = defaultConfig.AllowedBots
	}
	if config.BlockedIPs == nil {
		config.BlockedIPs = defaultConfig.BlockedIPs
	}
	if config.AllowedIPs == nil {
		config.AllowedIPs = defaultConfig.AllowedIPs
	}
	if config.MaxFileSize == 0 {
		config.MaxFileSize = defaultConfig.MaxFileSize
	}
	if config.Timeout == 0 {
		config.Timeout = defaultConfig.Timeout
	}

	return config, nil
}

// SaveConfig saves the configuration to a JSON file
func SaveConfig(config Config, filename string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, data, 0644)
}