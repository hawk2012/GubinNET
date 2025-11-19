package admin_ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

type AdminHandlers struct {
	DB *DatabaseManager
}

func NewAdminHandlers(db *DatabaseManager) *AdminHandlers {
	return &AdminHandlers{DB: db}
}

// ServeAdminUI serves the admin panel UI
func (ah *AdminHandlers) ServeAdminUI(w http.ResponseWriter, r *http.Request) {
	// Serve the admin panel HTML file
	http.ServeFile(w, r, "web/admin/index.html")
}

// GetDashboardData returns dashboard statistics
func (ah *AdminHandlers) GetDashboardData(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"server_status":      "running",
		"cache_size":         ah.DB.GetCacheSize(),
		"active_connections": 0, // This would come from server stats in a real implementation
		"total_requests":     0, // This would come from server stats in a real implementation
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// GetSettings returns all server settings
func (ah *AdminHandlers) GetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := ah.DB.GetAllSettings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

// UpdateSettings updates server settings
func (ah *AdminHandlers) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var settings map[string]string
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	for key, value := range settings {
		if err := ah.DB.SetSetting(key, value); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Settings updated successfully"))
}

// GetProxyRoutes returns all proxy routes
func (ah *AdminHandlers) GetProxyRoutes(w http.ResponseWriter, r *http.Request) {
	routes, err := ah.DB.GetAllProxyRoutes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(routes)
}

// AddProxyRoute adds a new proxy route
func (ah *AdminHandlers) AddProxyRoute(w http.ResponseWriter, r *http.Request) {
	var route ProxyRoute
	if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := ah.DB.AddProxyRoute(route.Path, route.TargetURL, route.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Proxy route added successfully"))
}

// UpdateProxyRoute updates an existing proxy route
func (ah *AdminHandlers) UpdateProxyRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "Invalid route ID", http.StatusBadRequest)
		return
	}

	var route ProxyRoute
	if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := ah.DB.UpdateProxyRoute(id, route.Path, route.TargetURL, route.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Proxy route updated successfully"))
}

// DeleteProxyRoute deletes a proxy route
func (ah *AdminHandlers) DeleteProxyRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "Invalid route ID", http.StatusBadRequest)
		return
	}

	if err := ah.DB.DeleteProxyRoute(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Proxy route deleted successfully"))
}

// GetCacheStats returns cache statistics
func (ah *AdminHandlers) GetCacheStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"file_count":    ah.DB.GetCacheFileCount(),
		"current_size":  ah.DB.GetCacheCurrentSize(),
		"max_size":      ah.DB.GetCacheMaxSize(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// ClearCache clears the entire cache
func (ah *AdminHandlers) ClearCache(w http.ResponseWriter, r *http.Request) {
	ah.DB.ClearCache()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Cache cleared successfully"))
}

// GetLogs returns server logs
func (ah *AdminHandlers) GetLogs(w http.ResponseWriter, r *http.Request) {
	level := r.URL.Query().Get("level")
	if level == "" {
		level = "all"
	}

	logs, err := ah.DB.GetLogs(level)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

// GetUsers returns all users
func (ah *AdminHandlers) GetUsers(w http.ResponseWriter, r *http.Request) {
	users, err := ah.DB.GetAllUsers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Remove password hashes from the response
	for i := range users {
		users[i].PasswordHash = ""
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// AddUser adds a new user
func (ah *AdminHandlers) AddUser(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate username
	if !isValidUsername(user.Username) {
		http.Error(w, "Invalid username", http.StatusBadRequest)
		return
	}

	// Validate password
	if !isValidPassword(user.Password) {
		http.Error(w, "Invalid password", http.StatusBadRequest)
		return
	}

	if err := ah.DB.AddUser(user.Username, user.Password); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User added successfully"))
}

// UpdateUser updates an existing user
func (ah *AdminHandlers) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate username
	if !isValidUsername(user.Username) {
		http.Error(w, "Invalid username", http.StatusBadRequest)
		return
	}

	// Only update password if provided
	if user.Password != "" {
		// Validate password
		if !isValidPassword(user.Password) {
			http.Error(w, "Invalid password", http.StatusBadRequest)
			return
		}
		if err := ah.DB.UpdateUser(id, user.Username, user.Password); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		// Update only username
		if err := ah.DB.UpdateUserUsername(id, user.Username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User updated successfully"))
}

// DeleteUser deletes a user
func (ah *AdminHandlers) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Prevent deleting the default admin user
	if id == 1 {
		http.Error(w, "Cannot delete default admin user", http.StatusBadRequest)
		return
	}

	if err := ah.DB.DeleteUser(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User deleted successfully"))
}

// isValidUsername validates username format
func isValidUsername(username string) bool {
	// Username should be 3-32 characters, alphanumeric and dots/underscores
	if len(username) < 3 || len(username) > 32 {
		return false
	}

	for _, r := range username {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_') {
			return false
		}
	}

	return true
}

// isValidPassword validates password strength
func isValidPassword(password string) bool {
	// Password should be at least 8 characters
	if len(password) < 8 {
		return false
	}

	// Check for at least one uppercase, one lowercase, one digit, and one special character
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, r := range password {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", r):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSpecial
}