package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	_ "github.com/lib/pq"
)

// DBConfig represents the database configuration for GubinNET server
type DBConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	DBName   string `json:"dbname"`
	SSLMode  string `json:"sslmode"`
}

// VirtualHost represents a virtual host configuration
type VirtualHost struct {
	ID          int    `json:"id"`
	Domain      string `json:"domain"`
	PublicDir   string `json:"public_dir"`
	Port        string `json:"port"`
	Enabled     bool   `json:"enabled"`
	SSLRequired bool   `json:"ssl_required"`
	SSLCert     string `json:"ssl_cert"`
	SSLKey      string `json:"ssl_key"`
}

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
	Database     DBConfig          `json:"database"`      // Database configuration for virtual hosts
}

// VirtualHostManager manages virtual hosts from database
type VirtualHostManager struct {
	db *sql.DB
}

// AntiDDoSConfig holds the configuration for anti-DDoS protection
type AntiDDoSConfig struct {
	Enabled          bool `json:"enabled"`
	MaxRequests      int  `json:"max_requests"`
	WindowSeconds    int  `json:"window_seconds"`
	BlockDuration    int  `json:"block_duration"` // in minutes
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

// ConnectDB connects to the database using the configuration
func (c *Config) ConnectDB() (*sql.DB, error) {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Database.Host, c.Database.Port, c.Database.User, c.Database.Password, c.Database.DBName, c.Database.SSLMode)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}

// NewVirtualHostManager creates a new VirtualHostManager
func NewVirtualHostManager(db *sql.DB) *VirtualHostManager {
	return &VirtualHostManager{db: db}
}

// GetVirtualHostByDomain retrieves a virtual host configuration by domain name
func (vhm *VirtualHostManager) GetVirtualHostByDomain(domain string) (*VirtualHost, error) {
	query := "SELECT id, domain, public_dir, port, enabled, ssl_required, ssl_cert, ssl_key FROM virtual_hosts WHERE domain = $1 AND enabled = true"
	row := vhm.db.QueryRow(query, domain)

	var vh VirtualHost
	err := row.Scan(&vh.ID, &vh.Domain, &vh.PublicDir, &vh.Port, &vh.Enabled, &vh.SSLRequired, &vh.SSLCert, &vh.SSLKey)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("virtual host for domain %s not found", domain)
		}
		return nil, err
	}

	return &vh, nil
}

// GetAllVirtualHosts retrieves all enabled virtual hosts
func (vhm *VirtualHostManager) GetAllVirtualHosts() ([]VirtualHost, error) {
	query := "SELECT id, domain, public_dir, port, enabled, ssl_required, ssl_cert, ssl_key FROM virtual_hosts WHERE enabled = true"
	rows, err := vhm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var virtualHosts []VirtualHost
	for rows.Next() {
		var vh VirtualHost
		err := rows.Scan(&vh.ID, &vh.Domain, &vh.PublicDir, &vh.Port, &vh.Enabled, &vh.SSLRequired, &vh.SSLCert, &vh.SSLKey)
		if err != nil {
			return nil, err
		}
		virtualHosts = append(virtualHosts, vh)
	}

	return virtualHosts, nil
}

// GetAllVirtualHostsIncludingDisabled retrieves all virtual hosts including disabled ones
func (vhm *VirtualHostManager) GetAllVirtualHostsIncludingDisabled() ([]VirtualHost, error) {
	query := "SELECT id, domain, public_dir, port, enabled, ssl_required, ssl_cert, ssl_key FROM virtual_hosts ORDER BY domain"
	rows, err := vhm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var virtualHosts []VirtualHost
	for rows.Next() {
		var vh VirtualHost
		err := rows.Scan(&vh.ID, &vh.Domain, &vh.PublicDir, &vh.Port, &vh.Enabled, &vh.SSLRequired, &vh.SSLCert, &vh.SSLKey)
		if err != nil {
			return nil, err
		}
		virtualHosts = append(virtualHosts, vh)
	}

	return virtualHosts, nil
}

// CreateVirtualHost creates a new virtual host
func (vhm *VirtualHostManager) CreateVirtualHost(vh *VirtualHost) error {
	query := `INSERT INTO virtual_hosts (domain, public_dir, port, enabled, ssl_required, ssl_cert, ssl_key) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7) 
			  RETURNING id`

	err := vhm.db.QueryRow(query,
		vh.Domain, vh.PublicDir, vh.Port, vh.Enabled, vh.SSLRequired, vh.SSLCert, vh.SSLKey,
	).Scan(&vh.ID)

	if err != nil {
		return fmt.Errorf("failed to create virtual host: %v", err)
	}

	log.Printf("Created virtual host: %s (ID: %d)", vh.Domain, vh.ID)
	return nil
}

// UpdateVirtualHost updates an existing virtual host
func (vhm *VirtualHostManager) UpdateVirtualHost(vh *VirtualHost) error {
	query := `UPDATE virtual_hosts 
			  SET domain = $1, public_dir = $2, port = $3, enabled = $4, ssl_required = $5, ssl_cert = $6, ssl_key = $7 
			  WHERE id = $8`

	result, err := vhm.db.Exec(query,
		vh.Domain, vh.PublicDir, vh.Port, vh.Enabled, vh.SSLRequired, vh.SSLCert, vh.SSLKey, vh.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update virtual host: %v", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("virtual host with ID %d not found", vh.ID)
	}

	log.Printf("Updated virtual host: %s (ID: %d)", vh.Domain, vh.ID)
	return nil
}

// DeleteVirtualHost deletes a virtual host by ID
func (vhm *VirtualHostManager) DeleteVirtualHost(id int) error {
	// First get the domain for logging
	var domain string
	err := vhm.db.QueryRow("SELECT domain FROM virtual_hosts WHERE id = $1", id).Scan(&domain)
	if err != nil {
		return fmt.Errorf("virtual host not found: %v", err)
	}

	query := "DELETE FROM virtual_hosts WHERE id = $1"
	result, err := vhm.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete virtual host: %v", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("virtual host with ID %d not found", id)
	}

	log.Printf("Deleted virtual host: %s (ID: %d)", domain, id)
	return nil
}

// DeleteVirtualHostByDomain deletes a virtual host by domain
func (vhm *VirtualHostManager) DeleteVirtualHostByDomain(domain string) error {
	query := "DELETE FROM virtual_hosts WHERE domain = $1"
	result, err := vhm.db.Exec(query, domain)
	if err != nil {
		return fmt.Errorf("failed to delete virtual host: %v", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("virtual host for domain %s not found", domain)
	}

	log.Printf("Deleted virtual host: %s", domain)
	return nil
}

// EnableVirtualHost enables a virtual host by domain
func (vhm *VirtualHostManager) EnableVirtualHost(domain string) error {
	query := "UPDATE virtual_hosts SET enabled = true WHERE domain = $1"
	result, err := vhm.db.Exec(query, domain)
	if err != nil {
		return fmt.Errorf("failed to enable virtual host: %v", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("virtual host for domain %s not found", domain)
	}

	log.Printf("Enabled virtual host: %s", domain)
	return nil
}

// DisableVirtualHost disables a virtual host by domain
func (vhm *VirtualHostManager) DisableVirtualHost(domain string) error {
	query := "UPDATE virtual_hosts SET enabled = false WHERE domain = $1"
	result, err := vhm.db.Exec(query, domain)
	if err != nil {
		return fmt.Errorf("failed to disable virtual host: %v", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("virtual host for domain %s not found", domain)
	}

	log.Printf("Disabled virtual host: %s", domain)
	return nil
}

// GetVirtualHostByID retrieves a virtual host by ID
func (vhm *VirtualHostManager) GetVirtualHostByID(id int) (*VirtualHost, error) {
	query := "SELECT id, domain, public_dir, port, enabled, ssl_required, ssl_cert, ssl_key FROM virtual_hosts WHERE id = $1"
	row := vhm.db.QueryRow(query, id)

	var vh VirtualHost
	err := row.Scan(&vh.ID, &vh.Domain, &vh.PublicDir, &vh.Port, &vh.Enabled, &vh.SSLRequired, &vh.SSLCert, &vh.SSLKey)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("virtual host with ID %d not found", id)
		}
		return nil, err
	}

	return &vh, nil
}

// ImportFromNginx imports virtual hosts from nginx configuration
func (vhm *VirtualHostManager) ImportFromNginx(nginxHosts []NginxVirtualHost) error {
	for _, nh := range nginxHosts {
		vh := &VirtualHost{
			Domain:      nh.Domain,
			PublicDir:   nh.PublicDir,
			Port:        nh.Port,
			Enabled:     true,
			SSLRequired: nh.SSLEnabled,
			SSLCert:     nh.SSLCertPath,
			SSLKey:      nh.SSLKeyPath,
		}

		// Check if already exists
		existing, err := vhm.GetVirtualHostByDomain(vh.Domain)
		if err == nil {
			// Update existing
			vh.ID = existing.ID
			if err := vhm.UpdateVirtualHost(vh); err != nil {
				log.Printf("Failed to update %s: %v", vh.Domain, err)
			}
		} else {
			// Create new
			if err := vhm.CreateVirtualHost(vh); err != nil {
				log.Printf("Failed to create %s: %v", vh.Domain, err)
			}
		}
	}

	return nil
}
