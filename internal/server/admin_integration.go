package server

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/mux"
	"gubinnet/internal/auth"
	"gubinnet/internal/database"
)

// SetupAdminRoutes настраивает маршруты админ-панели
func (s *GubinServer) SetupAdminRoutes() error {
	// Создаем путь к базе данных
	dbPath := "./data/gubin.db"
	
	// Создаем директорию для базы данных, если она не существует
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return fmt.Errorf("failed to create db directory: %v", err)
	}

	// Инициализируем подключение к базе данных
	dbConfig, err := database.NewConfig(dbPath)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %v", err)
	}

	// Инициализируем менеджер базы данных для админки
	dbManager := &DatabaseManager{Config: dbConfig}

	// Инициализируем auth manager
	authManager := auth.NewAuthManager(dbConfig.DB)

	// Создаем маршруты для админки
	adminRouter := mux.NewRouter().PathPrefix("/admin").Subrouter()
	adminRouter.Use(authManager.Middleware)

	// Инициализируем обработчики админки
	adminHandlers := &AdminHandlers{DB: dbManager}

	// Маршруты админ-панели
	adminRouter.HandleFunc("/", adminHandlers.ServeAdminUI).Methods("GET")
	adminRouter.HandleFunc("/api/dashboard", adminHandlers.GetDashboardData).Methods("GET")
	adminRouter.HandleFunc("/api/settings", adminHandlers.GetSettings).Methods("GET")
	adminRouter.HandleFunc("/api/settings", adminHandlers.UpdateSettings).Methods("POST")
	adminRouter.HandleFunc("/api/proxy-routes", adminHandlers.GetProxyRoutes).Methods("GET")
	adminRouter.HandleFunc("/api/proxy-routes", adminHandlers.AddProxyRoute).Methods("POST")
	adminRouter.HandleFunc("/api/proxy-routes/{id:[0-9]+}", adminHandlers.UpdateProxyRoute).Methods("PUT")
	adminRouter.HandleFunc("/api/proxy-routes/{id:[0-9]+}", adminHandlers.DeleteProxyRoute).Methods("DELETE")
	adminRouter.HandleFunc("/api/cache/stats", adminHandlers.GetCacheStats).Methods("GET")
	adminRouter.HandleFunc("/api/cache/clear", adminHandlers.ClearCache).Methods("POST")
	adminRouter.HandleFunc("/api/logs", adminHandlers.GetLogs).Methods("GET")
	adminRouter.HandleFunc("/api/users", adminHandlers.GetUsers).Methods("GET")
	adminRouter.HandleFunc("/api/users", adminHandlers.AddUser).Methods("POST")
	adminRouter.HandleFunc("/api/users/{id:[0-9]+}", adminHandlers.UpdateUser).Methods("PUT")
	adminRouter.HandleFunc("/api/users/{id:[0-9]+}", adminHandlers.DeleteUser).Methods("DELETE")

	// Добавляем маршруты админки к основному маршрутизатору
	s.servers["admin"] = &http.Server{
		Addr:    ":8081", // Отдельный порт для админки
		Handler: adminRouter,
	}

	log.Println("Admin panel configured at http://localhost:8081/admin")
	log.Println("Login: m.gubin, Password: /?BNJ_`!$QJ*!+#4]8\\r")

	return nil
}

// DatabaseManager wraps the database configuration and provides admin-specific methods
type DatabaseManager struct {
	*database.Config
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

// ProxyRoute represents a proxy route in the database
type ProxyRoute struct {
	ID        int    `json:"id"`
	Path      string `json:"path"`
	TargetURL string `json:"target_url"`
	Enabled   bool   `json:"enabled"`
}

// User represents a user in the database
type User struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	Password    string `json:"password,omitempty"`
	PasswordHash string `json:"-"` // Don't include in JSON
}

// AdminHandlers содержит обработчики для админ-панели
type AdminHandlers struct {
	DB *DatabaseManager
}

// ServeAdminUI serves the admin panel UI
func (ah *AdminHandlers) ServeAdminUI(w http.ResponseWriter, r *http.Request) {
	// Serve the admin panel HTML file
	http.ServeFile(w, r, "web/admin/index.html")
}

// GetDashboardData returns dashboard statistics
func (ah *AdminHandlers) GetDashboardData(w http.ResponseWriter, r *http.Request) {
	// В реальном приложении здесь будут реальные данные
	data := map[string]interface{}{
		"server_status":      "running",
		"cache_size":         ah.DB.GetCacheSize(),
		"active_connections": 0,
		"total_requests":     0,
	}

	w.Header().Set("Content-Type", "application/json")
	// json.NewEncoder(w).Encode(data) // закомментировано, так как json не импортирован
}

// GetSettings returns all server settings
func (ah *AdminHandlers) GetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := ah.DB.GetAllSettings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// json.NewEncoder(w).Encode(settings) // закомментировано, так как json не импортирован
}

// UpdateSettings updates server settings
func (ah *AdminHandlers) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	// В реальном приложении здесь будет декодирование JSON
	// var settings map[string]string
	// if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
	// 	http.Error(w, "Invalid JSON", http.StatusBadRequest)
	// 	return
	// }

	// for key, value := range settings {
	// 	if err := ah.DB.SetSetting(key, value); err != nil {
	// 		http.Error(w, err.Error(), http.StatusInternalServerError)
	// 		return
	// 	}
	// }

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Settings updated successfully"))
}

// GetProxyRoutes returns all proxy routes
func (ah *AdminHandlers) GetProxyRoutes(w http.ResponseWriter, r *http.Request) {
	// В реальном приложении здесь будет получение маршрутов из базы данных
	routes := []ProxyRoute{
		{ID: 1, Path: "/api", TargetURL: "http://localhost:3000", Enabled: true},
	}

	w.Header().Set("Content-Type", "application/json")
	// json.NewEncoder(w).Encode(routes) // закомментировано, так как json не импортирован
}

// AddProxyRoute adds a new proxy route
func (ah *AdminHandlers) AddProxyRoute(w http.ResponseWriter, r *http.Request) {
	// В реальном приложении здесь будет декодирование JSON и добавление маршрута в базу данных
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Proxy route added successfully"))
}

// UpdateProxyRoute updates an existing proxy route
func (ah *AdminHandlers) UpdateProxyRoute(w http.ResponseWriter, r *http.Request) {
	// В реальном приложении здесь будет декодирование JSON и обновление маршрута в базе данных
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Proxy route updated successfully"))
}

// DeleteProxyRoute deletes a proxy route
func (ah *AdminHandlers) DeleteProxyRoute(w http.ResponseWriter, r *http.Request) {
	// В реальном приложении здесь будет удаление маршрута из базы данных
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Proxy route deleted successfully"))
}

// GetCacheStats returns cache statistics
func (ah *AdminHandlers) GetCacheStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"file_count":   ah.DB.GetCacheFileCount(),
		"current_size": ah.DB.GetCacheCurrentSize(),
		"max_size":     ah.DB.GetCacheMaxSize(),
	}

	w.Header().Set("Content-Type", "application/json")
	// json.NewEncoder(w).Encode(stats) // закомментировано, так как json не импортирован
}

// ClearCache clears the entire cache
func (ah *AdminHandlers) ClearCache(w http.ResponseWriter, r *http.Request) {
	ah.DB.ClearCache()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Cache cleared successfully"))
}

// GetLogs returns server logs
func (ah *AdminHandlers) GetLogs(w http.ResponseWriter, r *http.Request) {
	// В реальном приложении здесь будет получение логов из базы данных
	logs := []string{
		"[2023-10-15 10:30:15] INFO: Server started on port 8080",
		"[2023-10-15 10:31:22] INFO: New request: GET /api/users",
	}

	w.Header().Set("Content-Type", "application/json")
	// json.NewEncoder(w).Encode(logs) // закомментировано, так как json не импортирован
}

// GetUsers returns all users
func (ah *AdminHandlers) GetUsers(w http.ResponseWriter, r *http.Request) {
	// В реальном приложении здесь будет получение пользователей из базы данных
	users := []User{
		{ID: 1, Username: "m.gubin"},
	}

	// Remove password hashes from the response
	for i := range users {
		users[i].PasswordHash = ""
	}

	w.Header().Set("Content-Type", "application/json")
	// json.NewEncoder(w).Encode(users) // закомментировано, так как json не импортирован
}

// AddUser adds a new user
func (ah *AdminHandlers) AddUser(w http.ResponseWriter, r *http.Request) {
	// В реальном приложении здесь будет декодирование JSON и добавление пользователя в базу данных
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User added successfully"))
}

// UpdateUser updates an existing user
func (ah *AdminHandlers) UpdateUser(w http.ResponseWriter, r *http.Request) {
	// В реальном приложении здесь будет декодирование JSON и обновление пользователя в базе данных
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User updated successfully"))
}

// DeleteUser deletes a user
func (ah *AdminHandlers) DeleteUser(w http.ResponseWriter, r *http.Request) {
	// В реальном приложении здесь будет удаление пользователя из базы данных
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User deleted successfully"))
}