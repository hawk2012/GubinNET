package server

import (
	"database/sql"
	"log"
	"strconv"
)

// LoadSettingsFromDB загружает настройки из SQLite базы данных
func LoadSettingsFromDB(db *sql.DB) *Settings {
	settings := &Settings{
		MaxCacheSizeMB: 100,  // Значение по умолчанию
		MaxFileSizeMB:  10,   // Значение по умолчанию
		ServerPort:     8080, // Значение по умолчанию
		EnableLogging:  true, // Значение по умолчанию
	}

	// Загружаем настройки из базы данных
	rows, err := db.Query("SELECT key, value FROM settings")
	if err != nil {
		log.Printf("Warning: failed to load settings from database: %v", err)
		return settings
	}
	defer rows.Close()

	for rows.Next() {
		var key, value string
		err := rows.Scan(&key, &value)
		if err != nil {
			log.Printf("Warning: failed to scan setting: %v", err)
			continue
		}

		switch key {
		case "max_cache_size_mb":
			if val, err := strconv.Atoi(value); err == nil {
				settings.MaxCacheSizeMB = val
			}
		case "max_file_size_mb":
			if val, err := strconv.Atoi(value); err == nil {
				settings.MaxFileSizeMB = val
			}
		case "server_port":
			if val, err := strconv.Atoi(value); err == nil {
				settings.ServerPort = val
			}
		case "enable_logging":
			settings.EnableLogging = value == "true"
		}
	}

	return settings
}

// LoadProxyConfigFromDB загружает конфигурацию прокси из SQLite базы данных
func LoadProxyConfigFromDB(db *sql.DB) *ProxyConfig {
	proxyConfig := &ProxyConfig{
		Routes: make(map[string]string),
	}

	// Загружаем маршруты прокси из базы данных
	rows, err := db.Query("SELECT path, target_url FROM proxy_routes WHERE enabled = 1")
	if err != nil {
		log.Printf("Warning: failed to load proxy routes from database: %v", err)
		return proxyConfig
	}
	defer rows.Close()

	for rows.Next() {
		var path, targetURL string
		err := rows.Scan(&path, &targetURL)
		if err != nil {
			log.Printf("Warning: failed to scan proxy route: %v", err)
			continue
		}

		proxyConfig.Routes[path] = targetURL
	}

	return proxyConfig
}