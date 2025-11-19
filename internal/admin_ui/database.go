package admin_ui

import (
	"database/sql"
	"time"

	"gubinnet/internal/database"
)

// ProxyRoute represents a proxy route in the database
type ProxyRoute struct {
	ID        int       `json:"id"`
	Path      string    `json:"path"`
	TargetURL string    `json:"target_url"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// User represents a user in the database
type User struct {
	ID          int       `json:"id"`
	Username    string    `json:"username"`
	Password    string    `json:"password,omitempty"`
	PasswordHash string   `json:"-"` // Don't include in JSON
	CreatedAt   time.Time `json:"created_at"`
	LastLogin   time.Time `json:"last_login"`
}

// DatabaseManager wraps the database configuration and provides admin-specific methods
type DatabaseManager struct {
	*database.Config
}

func NewDatabaseManager(config *database.Config) *DatabaseManager {
	return &DatabaseManager{Config: config}
}

// GetCacheSize returns the current cache size
func (dm *DatabaseManager) GetCacheSize() float64 {
	// This would interface with the cache system to get the current size
	// For now, returning a placeholder value
	return 24.5 // MB
}

// GetCacheFileCount returns the number of files in cache
func (dm *DatabaseManager) GetCacheFileCount() int {
	// This would interface with the cache system to get the file count
	// For now, returning a placeholder value
	return 42
}

// GetCacheCurrentSize returns the current cache size in MB
func (dm *DatabaseManager) GetCacheCurrentSize() float64 {
	// This would interface with the cache system to get the current size
	// For now, returning a placeholder value
	return 24.5 // MB
}

// GetCacheMaxSize returns the maximum cache size in MB
func (dm *DatabaseManager) GetCacheMaxSize() float64 {
	// This would interface with the cache system to get the max size
	// For now, returning a placeholder value
	return 100.0 // MB
}

// ClearCache clears the cache
func (dm *DatabaseManager) ClearCache() {
	// This would interface with the cache system to clear the cache
	// Implementation would go here
}

// GetAllProxyRoutes returns all proxy routes from the database
func (dm *DatabaseManager) GetAllProxyRoutes() ([]ProxyRoute, error) {
	rows, err := dm.DB.Query("SELECT id, path, target_url, enabled, created_at FROM proxy_routes ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var routes []ProxyRoute
	for rows.Next() {
		var route ProxyRoute
		var createdAt string
		err := rows.Scan(&route.ID, &route.Path, &route.TargetURL, &route.Enabled, &createdAt)
		if err != nil {
			return nil, err
		}
		
		// Parse the datetime string
		route.CreatedAt, err = time.Parse("2006-01-02 15:04:05", createdAt)
		if err != nil {
			return nil, err
		}
		
		routes = append(routes, route)
	}

	return routes, nil
}

// AddProxyRoute adds a new proxy route to the database
func (dm *DatabaseManager) AddProxyRoute(path, targetURL string, enabled bool) error {
	_, err := dm.DB.Exec("INSERT INTO proxy_routes (path, target_url, enabled) VALUES (?, ?, ?)", path, targetURL, enabled)
	return err
}

// UpdateProxyRoute updates an existing proxy route in the database
func (dm *DatabaseManager) UpdateProxyRoute(id int, path, targetURL string, enabled bool) error {
	_, err := dm.DB.Exec("UPDATE proxy_routes SET path = ?, target_url = ?, enabled = ? WHERE id = ?", path, targetURL, enabled, id)
	return err
}

// DeleteProxyRoute deletes a proxy route from the database
func (dm *DatabaseManager) DeleteProxyRoute(id int) error {
	_, err := dm.DB.Exec("DELETE FROM proxy_routes WHERE id = ?", id)
	return err
}

// GetLogs returns logs from the database based on level
func (dm *DatabaseManager) GetLogs(level string) ([]string, error) {
	var rows *sql.Rows
	var err error
	
	if level == "all" {
		rows, err = dm.DB.Query("SELECT level, message, timestamp FROM logs ORDER BY timestamp DESC LIMIT 100")
	} else {
		rows, err = dm.DB.Query("SELECT level, message, timestamp FROM logs WHERE level = ? ORDER BY timestamp DESC LIMIT 100", level)
	}
	
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []string
	for rows.Next() {
		var level, message, timestamp string
		err := rows.Scan(&level, &message, &timestamp)
		if err != nil {
			return nil, err
		}
		
		logs = append(logs, "["+timestamp+"] "+level+": "+message)
	}

	return logs, nil
}

// GetAllUsers returns all users from the database
func (dm *DatabaseManager) GetAllUsers() ([]User, error) {
	rows, err := dm.DB.Query("SELECT id, username, password_hash, created_at, last_login FROM users ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		var createdAt, lastLogin sql.NullString
		err := rows.Scan(&user.ID, &user.Username, &user.PasswordHash, &createdAt, &lastLogin)
		if err != nil {
			return nil, err
		}
		
		user.CreatedAt = time.Time{}
		user.LastLogin = time.Time{}
		
		if createdAt.Valid {
			user.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt.String)
		}
		
		if lastLogin.Valid {
			user.LastLogin, _ = time.Parse("2006-01-02 15:04:05", lastLogin.String)
		}
		
		users = append(users, user)
	}

	return users, nil
}

// AddUser adds a new user to the database
func (dm *DatabaseManager) AddUser(username, password string) error {
	// Hash the password before storing
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	
	_, err = dm.DB.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, hash)
	return err
}

// UpdateUser updates an existing user in the database
func (dm *DatabaseManager) UpdateUser(id int, username, password string) error {
	// Hash the password before storing
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	
	_, err = dm.DB.Exec("UPDATE users SET username = ?, password_hash = ? WHERE id = ?", username, hash, id)
	return err
}

// UpdateUserUsername updates only the username of an existing user
func (dm *DatabaseManager) UpdateUserUsername(id int, username string) error {
	_, err := dm.DB.Exec("UPDATE users SET username = ? WHERE id = ?", username, id)
	return err
}

// DeleteUser deletes a user from the database
func (dm *DatabaseManager) DeleteUser(id int) error {
	_, err := dm.DB.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

// hashPassword creates a hash of the password
// In a real implementation, this would use bcrypt
func hashPassword(password string) (string, error) {
	// For this implementation, we'll use the password as is
	// In a real application, you should use bcrypt or similar
	return password, nil
}