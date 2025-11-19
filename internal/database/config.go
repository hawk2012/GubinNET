package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

type Config struct {
	DB *sql.DB
}

func NewConfig(dbPath string) (*Config, error) {
	// Создаем директорию для базы данных, если она не существует
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Создаем таблицы, если они не существуют
	if err := createTables(db); err != nil {
		return nil, fmt.Errorf("failed to create tables: %v", err)
	}

	return &Config{DB: db}, nil
}

func createTables(db *sql.DB) error {
	// Таблица для настроек сервера
	settingsTable := `
	CREATE TABLE IF NOT EXISTS settings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		key TEXT UNIQUE NOT NULL,
		value TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	// Таблица для пользователей
	usersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login DATETIME
	);`

	// Таблица для логов
	logsTable := `
	CREATE TABLE IF NOT EXISTS logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		level TEXT NOT NULL,
		message TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	// Таблица для прокси-маршрутов
	proxyRoutesTable := `
	CREATE TABLE IF NOT EXISTS proxy_routes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		path TEXT UNIQUE NOT NULL,
		target_url TEXT NOT NULL,
		enabled BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	_, err := db.Exec(settingsTable)
	if err != nil {
		return fmt.Errorf("failed to create settings table: %v", err)
	}

	_, err = db.Exec(usersTable)
	if err != nil {
		return fmt.Errorf("failed to create users table: %v", err)
	}

	_, err = db.Exec(logsTable)
	if err != nil {
		return fmt.Errorf("failed to create logs table: %v", err)
	}

	_, err = db.Exec(proxyRoutesTable)
	if err != nil {
		return fmt.Errorf("failed to create proxy_routes table: %v", err)
	}

	// Добавляем пользователя по умолчанию, если таблица пуста
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check users count: %v", err)
	}

	if count == 0 {
		// Создаем хэш пароля для пользователя m.gubin
		// В реальном приложении нужно использовать bcrypt
		passwordHash := "/?BNJ_`!$QJ*!+#4]8\\r" // Здесь должен быть хэш, но для демонстрации оставим как есть
		_, err = db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", "m.gubin", passwordHash)
		if err != nil {
			return fmt.Errorf("failed to create default user: %v", err)
		}
	}

	return nil
}

func (c *Config) Close() error {
	return c.DB.Close()
}

// GetSetting возвращает значение настройки по ключу
func (c *Config) GetSetting(key string) (string, error) {
	var value string
	err := c.DB.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("setting %s not found", key)
		}
		return "", err
	}
	return value, nil
}

// SetSetting устанавливает значение настройки
func (c *Config) SetSetting(key, value string) error {
	_, err := c.DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", key, value)
	return err
}

// GetAllSettings возвращает все настройки
func (c *Config) GetAllSettings() (map[string]string, error) {
	rows, err := c.DB.Query("SELECT key, value FROM settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		settings[key] = value
	}

	return settings, nil
}