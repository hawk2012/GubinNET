package main

import (
	"compress/gzip"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"GubinNET/antiddos"
	"GubinNET/logger"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Метрики Prometheus
var (
	requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of HTTP requests",
	}, []string{"method", "path", "status"})
	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "Duration of HTTP requests",
		Buckets: []float64{0.1, 0.5, 1, 2.5, 5, 10},
	}, []string{"method", "path"})
	activeConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "http_active_connections",
		Help: "Number of active HTTP connections",
	})
)

// Конфигурация
type ConfigParser struct {
	DB *sql.DB
}

type VirtualHost struct {
	ServerName      string
	ListenPort      int
	Root            string
	Index           string
	TryFiles        []string
	UseSSL          bool
	CertPath        string
	KeyPath         string
	RedirectToHTTPS bool
}

// Основная структура сервера
type GubinNET struct {
	config             *ConfigParser
	logger             *logger.Logger
	cache              map[string]*cacheEntry
	mu                 sync.Mutex
	upgrader           websocket.Upgrader
	antiDDoS           *antiddos.AntiDDoS
	dbConnectionString string
}

type cacheEntry struct {
	content     []byte
	modTime     time.Time
	size        int64
	contentType string
}

// Загрузка конфигурации из MySQL
func (c *ConfigParser) Load(dbConnectionString string) error {
	var err error
	c.DB, err = sql.Open("mysql", dbConnectionString)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	return c.DB.Ping()
}

// Middleware для защиты от подозрительных запросов
func (g *GubinNET) securityMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.ToLower(r.URL.Path)
		blockedPatterns := []string{".env", "/shell", "/wordpress/wp-admin/setup-config.php"}
		for _, pattern := range blockedPatterns {
			if strings.Contains(path, pattern) {
				ip := getRealIP(r)
				g.logger.Warn("Blocked suspicious request", map[string]interface{}{
					"path": path,
					"ip":   ip,
				})
				g.serveErrorPage(w, r, http.StatusForbidden, "Access Denied")
				return
			}
		}
		next(w, r)
	}
}

// Запуск сервера
func (g *GubinNET) Start() {
	g.logger.Info("Starting server", nil)
	g.cache = make(map[string]*cacheEntry)

	// Канал для сигналов операционной системы
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	// Запуск HTTP-сервера
	go func() {
		httpServer := &http.Server{
			Addr:         ":80",
			Handler:      g.setupMiddleware(http.HandlerFunc(g.handleRequest)),
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		}
		g.logger.Info("HTTP server started on port 80", nil)
		err := httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			g.logger.Error("HTTP server error", map[string]interface{}{"error": err})
		}
	}()

	// Запуск HTTPS-сервера с поддержкой SNI
	go func() {
		// Создаем мапу для хранения сертификатов
		certMap := make(map[string]tls.Certificate)

		// Загружаем сертификаты из базы данных
		rows, err := g.config.DB.Query("SELECT server_name, cert_path, key_path FROM virtual_hosts WHERE use_ssl = TRUE")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var serverName, certPath, keyPath string
				err := rows.Scan(&serverName, &certPath, &keyPath)
				if err != nil {
					g.logger.Error("Failed to load SSL certificate", map[string]interface{}{
						"server_name": serverName,
						"error":       err,
					})
					continue
				}

				// Загружаем сертификат
				cert, err := tls.LoadX509KeyPair(certPath, keyPath)
				if err != nil {
					g.logger.Error("Failed to load SSL certificate", map[string]interface{}{
						"server_name": serverName,
						"error":       err,
					})
					continue
				}
				certMap[serverName] = cert
			}
		} else {
			g.logger.Error("Failed to query SSL certificates", map[string]interface{}{"error": err})
		}

		// Функция для получения сертификата по имени хоста
		getCertificate := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if cert, ok := certMap[hello.ServerName]; ok {
				return &cert, nil
			}
			g.logger.Warn("No certificate found for host", map[string]interface{}{
				"host": hello.ServerName,
			})
			return nil, fmt.Errorf("no certificate found for host: %s", hello.ServerName)
		}

		// Настройка TLS-конфигурации
		tlsConfig := &tls.Config{
			GetCertificate: getCertificate,
		}

		httpsServer := &http.Server{
			Addr:         ":443",
			Handler:      g.setupMiddleware(http.HandlerFunc(g.handleRequest)),
			TLSConfig:    tlsConfig,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		}

		g.logger.Info("HTTPS server started on port 443", nil)
		err = httpsServer.ListenAndServeTLS("", "") // Пустые строки, так как сертификаты загружаются через GetCertificate
		if err != nil && err != http.ErrServerClosed {
			g.logger.Error("HTTPS server error", map[string]interface{}{"error": err})
		}
	}()

	// Обработка сигналов
	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGHUP:
				g.logger.Info("Reloading configuration", nil)
				err := g.config.Load(g.dbConnectionString)
				if err != nil {
					g.logger.Error("Failed to reload config", map[string]interface{}{"error": err})
				} else {
					g.logger.Info("Configuration reloaded successfully", nil)
				}
			case os.Interrupt, syscall.SIGTERM:
				g.logger.Info("Shutting down server", nil)
				os.Exit(0)
			}
		}
	}()

	// Блокировка основного потока
	select {}
}

// Обработка запросов
func (g *GubinNET) handleRequest(w http.ResponseWriter, r *http.Request) {
	hostHeader := strings.Split(strings.TrimSuffix(r.Host, ";"), ":")[0]

	// Поиск виртуального хоста по заголовку Host
	var host *VirtualHost
	rows, err := g.config.DB.Query("SELECT server_name, listen_port, root_path, index_file, try_files, use_ssl, cert_path, key_path, redirect_to_https FROM virtual_hosts WHERE server_name = ?", hostHeader)
	if err != nil {
		g.logger.Error("Database query error", map[string]interface{}{"error": err})
		g.serveHostNotFoundPage(w, r)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var tryFilesStr string
		host = &VirtualHost{}
		err := rows.Scan(&host.ServerName, &host.ListenPort, &host.Root, &host.Index, &tryFilesStr, &host.UseSSL, &host.CertPath, &host.KeyPath, &host.RedirectToHTTPS)
		if err != nil {
			g.logger.Error("Database scan error", map[string]interface{}{"error": err})
			continue
		}
		host.TryFiles = strings.Split(tryFilesStr, ",")
		break
	}

	if host == nil {
		g.serveHostNotFoundPage(w, r)
		return
	}

	// Редирект на HTTPS
	if host.RedirectToHTTPS && r.TLS == nil {
		url := "https://" + hostHeader + r.URL.String()
		http.Redirect(w, r, url, http.StatusPermanentRedirect)
		return
	}

	g.serveFileOrSpa(w, r, host)
}

// Проксирование запросов
func (g *GubinNET) proxyRequest(w http.ResponseWriter, r *http.Request, proxyUrl string) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	req, err := http.NewRequest(r.Method, proxyUrl+r.URL.RequestURI(), r.Body)
	if err != nil {
		g.serveErrorPage(w, r, http.StatusBadGateway, "Proxy error")
		r.Body.Close()
		return
	}
	defer req.Body.Close()

	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		g.serveErrorPage(w, r, http.StatusBadGateway, "Proxy error")
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		w.Header()[key] = values
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// Служебные функции
func (g *GubinNET) serveErrorPage(w http.ResponseWriter, r *http.Request, statusCode int, message string) {
	g.logger.Info("Error page served", map[string]interface{}{
		"path":       r.URL.Path,
		"method":     r.Method,
		"status":     statusCode,
		"message":    message,
		"remote":     r.RemoteAddr,
		"user_agent": r.UserAgent(),
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error %d</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin: 50px; }
        h1 { color: #d9534f; }
        p { color: #555; }
    </style>
</head>
<body>
    <h1>Error %d</h1>
    <p>%s</p>
    <p>Server: GubinNET/1.4</p>
    <p>Request ID: %s</p>
</body>
</html>
`, statusCode, statusCode, message, w.Header().Get("X-Request-ID"))
	w.Write([]byte(html))
}

func (g *GubinNET) serveHostNotFoundPage(w http.ResponseWriter, r *http.Request) {
	g.logger.Info("Host not found page served", map[string]interface{}{
		"path":       r.URL.Path,
		"method":     r.Method,
		"remote":     r.RemoteAddr,
		"user_agent": r.UserAgent(),
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	html := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Host Not Found</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin: 50px; }
        h1 { color: #d9534f; }
        p { color: #555; }
    </style>
</head>
<body>
    <h1>Host Not Found</h1>
    <p>The requested host could not be found on this server.</p>
    <p>Server: GubinNET/1.4</p>
</body>
</html>
`
	w.Write([]byte(html))
}

func (g *GubinNET) serveFile(w http.ResponseWriter, r *http.Request, filePath string, fileInfo os.FileInfo) {
	g.mu.Lock()
	cached, found := g.cache[filePath]
	g.mu.Unlock()

	if !found || (fileInfo != nil && fileInfo.ModTime().After(cached.modTime)) {
		if fileInfo == nil {
			var err error
			fileInfo, err = os.Stat(filePath)
			if err != nil {
				g.serveErrorPage(w, r, http.StatusInternalServerError, "Internal Server Error")
				return
			}
		}

		content, err := os.ReadFile(filePath)
		if err != nil {
			g.serveErrorPage(w, r, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		cached = &cacheEntry{
			content:     content,
			modTime:     fileInfo.ModTime(),
			size:        fileInfo.Size(),
			contentType: getContentType(filePath),
		}

		g.mu.Lock()
		g.cache[filePath] = cached
		g.mu.Unlock()
	}

	w.Header().Set("Content-Type", cached.contentType)
	w.Header().Set("Content-Length", strconv.FormatInt(cached.size, 10))
	w.Header().Set("Last-Modified", cached.modTime.Format(http.TimeFormat))
	etag := fmt.Sprintf(`"%x-%x"`, cached.modTime.Unix(), cached.size)
	w.Header().Set("ETag", etag)

	if match := r.Header.Get("If-None-Match"); match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	if modSince := r.Header.Get("If-Modified-Since"); modSince != "" {
		modTime, err := http.ParseTime(modSince)
		if err == nil && cached.modTime.Before(modTime.Add(time.Second)) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		gz.Write(cached.content)
	} else {
		w.Write(cached.content)
	}
}

func (g *GubinNET) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = fmt.Sprintf("%d", time.Now().UnixNano())
		}
		g.logger.Info("Request started", map[string]interface{}{
			"request_id": requestID,
			"method":     r.Method,
			"path":       r.URL.Path,
			"remote":     r.RemoteAddr,
			"user_agent": r.UserAgent(),
		})
		w.Header().Set("X-Request-ID", requestID)
		ww := &responseWriterWrapper{w: w}
		next.ServeHTTP(ww, r)
		g.logger.Info("Request completed", map[string]interface{}{
			"request_id":  requestID,
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      ww.status,
			"duration_ms": time.Since(start).Milliseconds(),
		})
	})
}

func (g *GubinNET) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		activeConnections.Inc()
		defer activeConnections.Dec()
		ww := &responseWriterWrapper{w: w}
		next.ServeHTTP(ww, r)
		duration := time.Since(start).Seconds()
		requestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
		requestsTotal.WithLabelValues(r.Method, r.URL.Path, strconv.Itoa(ww.status)).Inc()
	})
}

func (g *GubinNET) serveFileOrSpa(w http.ResponseWriter, r *http.Request, host *VirtualHost) {
	webRootPath := host.Root
	if webRootPath == "" {
		g.serveErrorPage(w, r, http.StatusInternalServerError, "Server configuration error")
		return
	}

	requestPath := filepath.Clean(strings.TrimLeft(r.URL.Path, "/"))
	fullPath := filepath.Join(webRootPath, requestPath)
	fileInfo, err := os.Stat(fullPath)
	if err == nil && !fileInfo.IsDir() {
		g.serveFile(w, r, fullPath, fileInfo)
		return
	}

	if len(host.TryFiles) > 0 {
		for _, tryFile := range host.TryFiles {
			if tryFile == "$uri" {
				continue
			}
			tryPath := filepath.Join(webRootPath, tryFile)
			if _, err := os.Stat(tryPath); err == nil {
				g.serveFile(w, r, tryPath, nil)
				return
			}
		}
	}

	g.serveErrorPage(w, r, http.StatusNotFound, "File Not Found")
}

func getRealIP(r *http.Request) string {
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip = strings.Split(r.RemoteAddr, ":")[0]
	}
	return ip
}

func (g *GubinNET) setupMiddleware(handler http.Handler) http.Handler {
	if g.antiDDoS == nil {
		g.logger.Error("AntiDDoS is not initialized", nil)
		os.Exit(1)
	}

	return g.securityMiddleware(
		g.antiDDoS.Middleware(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				g.loggingMiddleware(
					g.metricsMiddleware(handler),
				).ServeHTTP(w, r)
			}),
		),
	)
}

func getContentType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".html":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".json":
		return "application/json"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	default:
		return "application/octet-stream"
	}
}

type responseWriterWrapper struct {
	w      http.ResponseWriter
	status int
}

func (w *responseWriterWrapper) Header() http.Header {
	return w.w.Header()
}

func (w *responseWriterWrapper) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.w.Write(b)
}

func (w *responseWriterWrapper) WriteHeader(statusCode int) {
	w.status = statusCode
	w.w.WriteHeader(statusCode)
}

func main() {
	logger := logger.NewLogger("/etc/gubinnet/logs")
	if logger == nil {
		fmt.Println("Failed to initialize logger")
		os.Exit(1)
	}

	config := &ConfigParser{}

	// Строка подключения к базе данных
	dbConnectionString := "user:password@tcp(127.0.0.1:3306)/gubinnet"

	// Загрузка конфигурации
	err := config.Load(dbConnectionString)
	if err != nil {
		logger.Error("Failed to load config", map[string]interface{}{
			"error": err,
		})
		os.Exit(1)
	}

	// Инициализация AntiDDoS
	defaultConfig := &antiddos.AntiDDoSConfig{
		MaxRequestsPerSecond: 100,
		BlockDuration:        60 * time.Second,
	}
	antiDDoS := antiddos.NewAntiDDoS(defaultConfig, logger)

	server := &GubinNET{
		config:   config,
		logger:   logger,
		cache:    make(map[string]*cacheEntry),
		antiDDoS: antiDDoS,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		dbConnectionString: dbConnectionString,
	}

	server.Start()
	select {}
}
