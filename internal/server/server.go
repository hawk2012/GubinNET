package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"gubinnet/internal/config"
	"gubinnet/internal/logging"
	"gubinnet/internal/metrics"
	"gubinnet/internal/modules"
	"gubinnet/internal/security"
)

// GubinServer основной сервер приложения
type GubinServer struct {
	config   *config.Config
	logger   *logging.Logger
	antiDDoS *security.AntiDDoS
	cache    *FileCache
	modules  *modules.Manager
	servers  map[string]*http.Server
	mu       sync.RWMutex
}

// New создает новый экземпляр сервера
func New(cfg *config.Config, logger *logging.Logger) (*GubinServer, error) {
	// Инициализация анти-DDoS
	antiDDoS, err := security.NewAntiDDoS(cfg.AntiDDoS)
	if err != nil {
		return nil, fmt.Errorf("create anti-ddos: %w", err)
	}

	// Инициализация кэша
	cache := NewFileCache()
	cache.StartCleanupWorker()

	// Инициализация менеджера модулей
	moduleManager := modules.NewManager("/etc/gubinnet/modules", logger)

	// Запуск системных метрик
	metrics.StartSystemMetrics()

	srv := &GubinServer{
		config:   cfg,
		logger:   logger,
		antiDDoS: antiDDoS,
		cache:    cache,
		modules:  moduleManager,
		servers:  make(map[string]*http.Server),
	}

	// Настройка админ-панели с SQLite и аутентификацией
	if err := srv.SetupAdminRoutes(); err != nil {
		logger.Error("Failed to setup admin routes", map[string]interface{}{
			"error": err,
		})
		// Продолжаем работу, даже если админка не настроена
	}

	return srv, nil
}

// Start запускает сервер
func (s *GubinServer) Start() error {
	s.logger.Info("Starting GubinNET server", nil)

	// Запуск фоновых модулей
	if err := s.modules.StartAll(); err != nil {
		return fmt.Errorf("start modules: %w", err)
	}

	// Запуск виртуальных хостов
	for _, host := range s.config.VirtualHosts {
		if err := s.startVirtualHost(host); err != nil {
			return fmt.Errorf("start virtual host %s: %w", host.ServerName, err)
		}
	}

	s.logger.Info("All virtual hosts started successfully", nil)
	return nil
}

// Shutdown gracefully останавливает сервер
func (s *GubinServer) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down server", nil)

	// Остановка модулей
	s.modules.StopAll()

	// Остановка серверов
	var wg sync.WaitGroup
	errorChan := make(chan error, len(s.servers))

	for name, server := range s.servers {
		wg.Add(1)
		go func(name string, srv *http.Server) {
			defer wg.Done()

			s.logger.Info("Shutting down server", map[string]interface{}{
				"server": name,
			})

			if err := srv.Shutdown(ctx); err != nil {
				errorChan <- fmt.Errorf("server %s: %w", name, err)
			}
		}(name, server)
	}

	// Ожидаем завершения всех shutdown операций
	wg.Wait()
	close(errorChan)

	// Собираем ошибки
	var errors []string
	for err := range errorChan {
		errors = append(errors, err.Error())
	}

	if len(errors) > 0 {
		return fmt.Errorf("shutdown completed with errors: %s", strings.Join(errors, "; "))
	}

	s.logger.Info("Server shutdown completed", nil)
	return nil
}

// Reload перезагружает конфигурацию
func (s *GubinServer) Reload(newConfig *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("Reloading server configuration", nil)

	// Обновляем конфигурацию
	s.config = newConfig

	// Перезапускаем виртуальные хосты
	for serverName := range s.servers {
		if _, exists := newConfig.VirtualHosts[serverName]; !exists {
			s.stopVirtualHost(serverName)
		}
	}

	for serverName, host := range newConfig.VirtualHosts {
		if _, exists := s.servers[serverName]; !exists {
			s.startVirtualHost(host)
		}
	}

	s.logger.Info("Configuration reloaded successfully", nil)
	return nil
}

// startVirtualHost запускает виртуальный хост
func (s *GubinServer) startVirtualHost(host *config.VirtualHost) error {
	handler := s.createHandler()

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", host.ListenPort),
		Handler:      handler,
		ReadTimeout:  s.config.Server.ReadTimeout,
		WriteTimeout: s.config.Server.WriteTimeout,
		IdleTimeout:  s.config.Server.IdleTimeout,
	}

	// Настройка TLS если требуется
	if host.UseSSL {
		cert, err := tls.LoadX509KeyPair(host.CertPath, host.KeyPath)
		if err != nil {
			return fmt.Errorf("load TLS certificate: %w", err)
		}

		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		}
	}

	s.mu.Lock()
	s.servers[host.ServerName] = server
	s.mu.Unlock()

	// Запуск сервера в отдельной goroutine
	go func() {
		var err error

		s.logger.Info("Starting virtual host", map[string]interface{}{
			"server_name": host.ServerName,
			"port":        host.ListenPort,
			"ssl":         host.UseSSL,
		})

		if host.UseSSL {
			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			s.logger.Error("Virtual host error", map[string]interface{}{
				"server_name": host.ServerName,
				"error":       err,
			})
		}
	}()

	return nil
}

// stopVirtualHost останавливает виртуальный хост
func (s *GubinServer) stopVirtualHost(serverName string) {
	s.mu.Lock()
	server, exists := s.servers[serverName]
	if exists {
		delete(s.servers, serverName)
	}
	s.mu.Unlock()

	if exists {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			s.logger.Error("Failed to stop virtual host", map[string]interface{}{
				"server_name": serverName,
				"error":       err,
			})
		} else {
			s.logger.Info("Virtual host stopped", map[string]interface{}{
				"server_name": serverName,
			})
		}
	}
}

// createHandler создает HTTP handler с middleware
func (s *GubinServer) createHandler() http.Handler {
	mux := http.NewServeMux()

	// Endpoint для метрик Prometheus
	mux.Handle("/metrics", metrics.Handler())

	// Health check endpoint
	mux.HandleFunc("/health", s.healthHandler)

	// API для управления модулями
	mux.HandleFunc("/api/modules", s.modulesHandler)

	// Основной обработчик запросов
	mux.HandleFunc("/", s.handleRequest)

	// Применяем middleware в правильном порядке (снизу вверх):
	// 1. Security headers
	// 2. Logging
	// 3. Metrics
	// 4. Anti-DDoS
	// 5. Security middleware

	handler := security.SecurityHeadersMiddleware(mux)
	handler = s.loggingMiddleware(handler)
	handler = metrics.HTTPMiddleware(handler)
	handler = s.antiDDoS.Middleware(handler)
	handler = s.securityMiddleware(handler)

	return handler
}

// healthHandler обработчик health check
func (s *GubinServer) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "2.0.0",
		"server":    "GubinNET",
	}

	// Проверяем здоровье модулей
	modulesHealth := make(map[string]string)
	allHealthy := true

	for name, module := range s.modules.ListModules() {
		if module.Running {
			modulesHealth[name] = "healthy"
		} else {
			modulesHealth[name] = "unhealthy"
			allHealthy = false
		}
	}

	if !allHealthy {
		health["status"] = "degraded"
	}
	health["modules"] = modulesHealth

	// Сериализуем JSON ответ
	jsonData, err := json.MarshalIndent(health, "", "  ")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Write(jsonData)
}

// modulesHandler обработчик API для модулей
func (s *GubinServer) modulesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		// Получение списка модулей
		modules := s.modules.ListModules()
		jsonData, err := json.Marshal(modules)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Write(jsonData)

	case "POST":
		// Запуск модуля
		var request struct {
			Module string `json:"module"`
		}

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if err := s.modules.StartModule(request.Module); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "started"})

	case "DELETE":
		// Остановка модуля
		moduleName := r.URL.Query().Get("module")
		if moduleName == "" {
			http.Error(w, "Module name required", http.StatusBadRequest)
			return
		}

		if err := s.modules.StopModule(moduleName); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// GetStats возвращает статистику сервера
func (s *GubinServer) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := map[string]interface{}{
		"virtual_hosts": len(s.servers),
		"modules":       len(s.modules.ListModules()),
		"cache_entries": s.cache.Count(),
		"anti_ddos":     s.antiDDoS.GetStats(),
	}

	return stats
}
