package main

import (
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"GubinNET/antiddos"
	"GubinNET/logger"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Constants for configuration directory
const (
	ConfigDir = "/etc/gubinnet/config"
	LogDir    = "/etc/gubinnet/logs"
)

// Prometheus Metrics
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

// Configuration Parser
type ConfigParser struct {
	VirtualHosts map[string]*VirtualHost
}

// Virtual Host Structure
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
	ProxyURL        string
}

// Main Server Structure
type GubinNET struct {
	config   *ConfigParser
	logger   *logger.Logger
	cache    map[string]*cacheEntry
	mu       sync.Mutex
	antiDDoS *antiddos.AntiDDoS
}

type cacheEntry struct {
	content     []byte
	modTime     time.Time
	size        int64
	contentType string
}

func main() {
	// Initialize logger
	logger := logger.NewLogger(LogDir)
	if logger == nil {
		fmt.Println("Failed to initialize logger")
		os.Exit(1)
	}
	// Load configuration
	config := loadConfiguration(ConfigDir, logger)
	if config == nil {
		logger.Error("Failed to load configuration", nil)
		os.Exit(1)
	}
	// Initialize AntiDDoS
	defaultConfig := &antiddos.AntiDDoSConfig{
		MaxRequestsPerSecond: 100,
		BlockDuration:        60 * time.Second,
	}
	antiDDoS := antiddos.NewAntiDDoS(defaultConfig, logger)
	// Initialize server
	server := &GubinNET{
		config:   config,
		logger:   logger,
		cache:    make(map[string]*cacheEntry),
		antiDDoS: antiDDoS,
	}
	// Start server
	server.Start()
	// Handle OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	for sig := range sigChan {
		switch sig {
		case syscall.SIGHUP:
			logger.Info("Reloading configuration", nil)
			newConfig := loadConfiguration(ConfigDir, logger)
			if newConfig != nil {
				server.config = newConfig
				logger.Info("Configuration reloaded successfully", nil)
			} else {
				logger.Error("Failed to reload configuration", nil)
			}
		case os.Interrupt, syscall.SIGTERM:
			logger.Info("Shutting down server", nil)
			os.Exit(0)
		}
	}
}

// Load configuration from INI-like files
func loadConfiguration(configDir string, logger *logger.Logger) *ConfigParser {
	config := &ConfigParser{
		VirtualHosts: make(map[string]*VirtualHost),
	}
	files, err := os.ReadDir(configDir)
	if err != nil {
		logger.Error("Failed to read configuration directory", map[string]interface{}{"error": err})
		return nil
	}
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".ini") {
			host, err := parseVirtualHost(filepath.Join(configDir, file.Name()))
			if err != nil {
				logger.Warn("Failed to parse virtual host configuration", map[string]interface{}{
					"file":  file.Name(),
					"error": err,
				})
				continue
			}
			// Check if root path exists
			if host.Root != "" {
				if _, err := os.Stat(host.Root); os.IsNotExist(err) {
					logger.Error("Root path does not exist", map[string]interface{}{
						"server_name": host.ServerName,
						"root_path":   host.Root,
					})
					continue
				}
			}
			config.VirtualHosts[host.ServerName] = host
		}
	}
	return config
}

// Parse virtual host configuration from INI-like file
func parseVirtualHost(filePath string) (*VirtualHost, error) {
	host := &VirtualHost{}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch key {
		case "server_name":
			host.ServerName = value
		case "listen_port":
			port, _ := strconv.Atoi(value)
			host.ListenPort = port
		case "root_path":
			host.Root = value
		case "index_file":
			host.Index = value
		case "try_files":
			host.TryFiles = strings.Split(value, ",")
		case "use_ssl":
			host.UseSSL = value == "true"
		case "cert_path":
			host.CertPath = value
		case "key_path":
			host.KeyPath = value
		case "redirect_to_https":
			host.RedirectToHTTPS = value == "true"
		case "proxy_url":
			host.ProxyURL = value
		}
	}
	return host, nil
}

// Start the server
func (g *GubinNET) Start() {
	g.logger.Info("Starting server", nil)
	// Start HTTP server
	go func() {
		httpServer := &http.Server{
			Addr:         ":80",
			Handler:      g.setupMiddleware(http.HandlerFunc(g.handleRequest)),
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		g.logger.Info("HTTP server started on port 80", nil)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			g.logger.Error("HTTP server error", map[string]interface{}{"error": err})
		}
	}()
	// Start HTTPS server with SNI support
	go func() {
		certMap := make(map[string]tls.Certificate)
		for _, host := range g.config.VirtualHosts {
			if host.UseSSL {
				cert, err := tls.LoadX509KeyPair(host.CertPath, host.KeyPath)
				if err != nil {
					g.logger.Error("Failed to load SSL certificate", map[string]interface{}{
						"server_name": host.ServerName,
						"error":       err,
					})
					continue
				}
				certMap[host.ServerName] = cert
			}
		}
		getCertificate := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if cert, ok := certMap[hello.ServerName]; ok {
				return &cert, nil
			}
			g.logger.Warn("No certificate found for host", map[string]interface{}{
				"host": hello.ServerName,
			})
			return nil, fmt.Errorf("no certificate found for host: %s", hello.ServerName)
		}
		tlsConfig := &tls.Config{
			GetCertificate: getCertificate,
			MinVersion:     tls.VersionTLS12,
		}
		httpsServer := &http.Server{
			Addr:         ":443",
			Handler:      g.setupMiddleware(http.HandlerFunc(g.handleRequest)),
			TLSConfig:    tlsConfig,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		g.logger.Info("HTTPS server started on port 443", nil)
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			g.logger.Error("HTTPS server error", map[string]interface{}{"error": err})
		}
	}()
}

// Handle incoming requests
func (g *GubinNET) handleRequest(w http.ResponseWriter, r *http.Request) {
	defer func(start time.Time) {
		duration := time.Since(start).Seconds()
		requestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
	}(time.Now())
	// Generate unique Request ID
	requestID := uuid.New().String()
	w.Header().Set("X-Request-ID", requestID)
	hostHeader := strings.Split(strings.TrimSuffix(r.Host, ";"), ":")[0]
	host, exists := g.config.VirtualHosts[hostHeader]
	if !exists || host.Root == "" {
		g.serveHostNotFoundPage(w, r, requestID)
		return
	}
	// Redirect to HTTPS
	if host.RedirectToHTTPS && r.TLS == nil {
		url := "https://" + hostHeader + r.URL.String()
		http.Redirect(w, r, url, http.StatusPermanentRedirect)
		return
	}
	g.serveFileOrSpa(w, r, host, requestID)
}

// Serve file or SPA
func (g *GubinNET) serveFileOrSpa(w http.ResponseWriter, r *http.Request, host *VirtualHost, requestID string) {
	webRootPath := host.Root
	if webRootPath == "" {
		g.serveErrorPage(w, r, http.StatusInternalServerError, "Server configuration error", "", requestID)
		return
	}
	requestPath := filepath.Clean(strings.TrimLeft(r.URL.Path, "/"))
	fullPath := filepath.Join(webRootPath, requestPath)
	fileInfo, err := os.Stat(fullPath)

	// Check for index.html in directories
	if err == nil && fileInfo.IsDir() {
		indexFiles := []string{"index.html", "index.htm", "default.htm"}
		for _, index := range indexFiles {
			indexPath := filepath.Join(fullPath, index)
			if stat, err := os.Stat(indexPath); err == nil && !stat.IsDir() {
				fullPath = indexPath
				fileInfo = stat
				break
			}
		}
	}

	if err == nil && !fileInfo.IsDir() {
		// Handle PHP
		if strings.HasSuffix(fullPath, ".php") {
			g.handlePHP(w, r, fullPath, requestID)
			return
		}
		// Handle .NET applications
		if strings.HasSuffix(fullPath, ".aspx") || strings.HasSuffix(fullPath, ".cshtml") {
			g.handleDotNet(w, r, fullPath, requestID)
			return
		}
		// Handle Node.js applications
		if strings.HasSuffix(fullPath, ".js") {
			g.handleNodeJS(w, r, fullPath, requestID)
			return
		}
		g.serveFile(w, r, fullPath, fileInfo, requestID)
		return
	}
	if len(host.TryFiles) > 0 {
		for _, tryFile := range host.TryFiles {
			tryPath := filepath.Join(webRootPath, strings.Replace(tryFile, "$uri", requestPath, 1))
			if _, err := os.Stat(tryPath); err == nil {
				g.serveFile(w, r, tryPath, nil, requestID)
				return
			}
		}
	}
	// Proxy if proxy_url is set
	if host.ProxyURL != "" {
		g.handleProxy(w, r, host.ProxyURL, requestID)
		return
	}
	g.serveErrorPage(w, r, http.StatusNotFound, "File Not Found", fmt.Sprintf("File '%s' does not exist in root path '%s'", requestPath, webRootPath), requestID)
}

// Handle PHP via FastCGI
func (g *GubinNET) handlePHP(w http.ResponseWriter, r *http.Request, filePath string, requestID string) {
	cmd := exec.Command("php-cgi")
	env := map[string]string{
		"SCRIPT_FILENAME":   filePath,
		"SERVER_SOFTWARE":   "GubinNET/1.5",
		"GATEWAY_INTERFACE": "CGI/1.1",
		"REQUEST_METHOD":    r.Method,
		"QUERY_STRING":      r.URL.RawQuery,
		"REMOTE_ADDR":       getRealIP(r),
		"REDIRECT_STATUS":   "200",
	}
	cmd.Env = append(os.Environ(), envToEnvSlice(env)...)
	cmd.Stdin = r.Body
	cmd.Stdout = w
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		g.logErrorWithStackTrace("Failed to execute PHP-CGI", map[string]interface{}{
			"error":      err,
			"path":       filePath,
			"request_id": requestID,
		})
		g.serveErrorPage(w, r, http.StatusInternalServerError, "Internal Server Error", "", requestID)
	}
}

// Handle .NET applications
func (g *GubinNET) handleDotNet(w http.ResponseWriter, r *http.Request, filePath string, requestID string) {
	cmd := exec.Command("dotnet", filePath)
	env := map[string]string{
		"ASPNETCORE_URLS":        "http://localhost:5000",
		"ASPNETCORE_ENVIRONMENT": "Production",
		"REQUEST_METHOD":         r.Method,
		"QUERY_STRING":           r.URL.RawQuery,
		"REMOTE_ADDR":            getRealIP(r),
	}
	cmd.Env = append(os.Environ(), envToEnvSlice(env)...)
	cmd.Stdin = r.Body
	cmd.Stdout = w
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		g.logErrorWithStackTrace("Failed to execute .NET application", map[string]interface{}{
			"error":      err,
			"path":       filePath,
			"request_id": requestID,
		})
		g.serveErrorPage(w, r, http.StatusInternalServerError, "Internal Server Error", "", requestID)
	}
}

// Handle Node.js applications
func (g *GubinNET) handleNodeJS(w http.ResponseWriter, r *http.Request, filePath string, requestID string) {
	cmd := exec.Command("node", filePath)
	env := map[string]string{
		"NODE_ENV":       "production",
		"REQUEST_METHOD": r.Method,
		"QUERY_STRING":   r.URL.RawQuery,
		"REMOTE_ADDR":    getRealIP(r),
	}
	cmd.Env = append(os.Environ(), envToEnvSlice(env)...)
	cmd.Stdin = r.Body
	cmd.Stdout = w
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		g.logErrorWithStackTrace("Failed to execute Node.js application", map[string]interface{}{
			"error":      err,
			"path":       filePath,
			"request_id": requestID,
		})
		g.serveErrorPage(w, r, http.StatusInternalServerError, "Internal Server Error", "", requestID)
	}
}

// Handle proxying
func (g *GubinNET) handleProxy(w http.ResponseWriter, r *http.Request, proxyURL string, requestID string) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequest(r.Method, proxyURL+r.URL.String(), r.Body)
	if err != nil {
		g.logErrorWithStackTrace("Failed to create proxy request", map[string]interface{}{
			"error":      err,
			"url":        proxyURL,
			"request_id": requestID,
		})
		g.serveErrorPage(w, r, http.StatusInternalServerError, "Internal Server Error", "", requestID)
		return
	}
	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		g.logErrorWithStackTrace("Failed to proxy request", map[string]interface{}{
			"error":      err,
			"url":        proxyURL,
			"request_id": requestID,
		})
		g.serveErrorPage(w, r, http.StatusBadGateway, "Bad Gateway", "", requestID)
		return
	}
	defer resp.Body.Close()
	// Copy response
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
}

// Middleware Setup
func (g *GubinNET) setupMiddleware(handler http.Handler) http.Handler {
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

// Security Middleware
func (g *GubinNET) securityMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.ToLower(r.URL.Path)
		blockedPatterns := []string{".env", "/shell", "/wordpress/wp-admin/setup-config.php", "/device.rsp"}
		for _, pattern := range blockedPatterns {
			if strings.Contains(path, pattern) {
				ip := getRealIP(r)
				g.logErrorWithStackTrace("Blocked suspicious request", map[string]interface{}{
					"path":       path,
					"ip":         ip,
					"request_id": w.Header().Get("X-Request-ID"),
				})
				g.serveErrorPage(w, r, http.StatusForbidden, "Access Denied", "", w.Header().Get("X-Request-ID"))
				return
			}
		}
		next(w, r)
	}
}

// Logging Middleware
func (g *GubinNET) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriterWrapper{w: w}
		next.ServeHTTP(wrapped, r)
		duration := time.Since(start).Seconds()
		statusCode := wrapped.status
		if statusCode == 0 {
			statusCode = http.StatusOK
		}
		requestsTotal.WithLabelValues(r.Method, r.URL.Path, strconv.Itoa(statusCode)).Inc()
		activeConnections.Dec()
		g.logger.Info("Request processed", map[string]interface{}{
			"method":     r.Method,
			"path":       r.URL.Path,
			"status":     statusCode,
			"duration":   duration,
			"remote":     r.RemoteAddr,
			"user_agent": r.UserAgent(),
			"request_id": w.Header().Get("X-Request-ID"),
		})
	})
}

// Metrics Middleware
func (g *GubinNET) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		activeConnections.Inc()
		defer activeConnections.Dec()
		next.ServeHTTP(w, r)
	})
}

// Utility Functions
func getRealIP(r *http.Request) string {
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip = strings.Split(r.RemoteAddr, ":")[0]
	}
	return ip
}

func envToEnvSlice(env map[string]string) []string {
	var envSlice []string
	for key, value := range env {
		envSlice = append(envSlice, fmt.Sprintf("%s=%s", key, value))
	}
	return envSlice
}

// Response Writer Wrapper
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

// Serve File
func (g *GubinNET) serveFile(w http.ResponseWriter, r *http.Request, filePath string, fileInfo os.FileInfo, requestID string) {
	g.mu.Lock()
	var cached *cacheEntry
	var found bool
	cached, found = g.cache[filePath]
	g.mu.Unlock()
	if !found || (fileInfo != nil && fileInfo.ModTime().After(cached.modTime)) {
		if fileInfo == nil {
			var err error
			fileInfo, err = os.Stat(filePath)
			if err != nil {
				g.logErrorWithStackTrace("Failed to stat file", map[string]interface{}{
					"error":      err,
					"path":       filePath,
					"request_id": requestID,
				})
				g.serveErrorPage(w, r, http.StatusInternalServerError, "Internal Server Error", "", requestID)
				return
			}
		}
		content, err := os.ReadFile(filePath)
		if err != nil {
			g.logErrorWithStackTrace("Failed to read file", map[string]interface{}{
				"error":      err,
				"path":       filePath,
				"request_id": requestID,
			})
			g.serveErrorPage(w, r, http.StatusInternalServerError, "Internal Server Error", "", requestID)
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

// Serve Error Page
func (g *GubinNET) serveErrorPage(w http.ResponseWriter, r *http.Request, statusCode int, message string, details string, requestID string) {
	g.logErrorWithStackTrace("Error page served", map[string]interface{}{
		"path":       r.URL.Path,
		"method":     r.Method,
		"status":     statusCode,
		"message":    message,
		"details":    details,
		"remote":     r.RemoteAddr,
		"user_agent": r.UserAgent(),
		"request_id": requestID,
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
    <p>Details: %s</p>
    <p>Server: GubinNET/1.5</p>
    <p>Request ID: %s</p>
</body>
</html>
`, statusCode, statusCode, message, details, requestID)
	w.Write([]byte(html))
}

// Serve Host Not Found Page
func (g *GubinNET) serveHostNotFoundPage(w http.ResponseWriter, r *http.Request, requestID string) {
	g.logErrorWithStackTrace("Host not found page served", map[string]interface{}{
		"path":       r.URL.Path,
		"method":     r.Method,
		"remote":     r.RemoteAddr,
		"user_agent": r.UserAgent(),
		"request_id": requestID,
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
    <p>Server: GubinNET/1.5</p>
</body>
</html>
`
	w.Write([]byte(html))
}

// Get Content Type
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
	case ".php":
		return "text/html; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

// Log Error with Stack Trace
func (g *GubinNET) logErrorWithStackTrace(message string, fields map[string]interface{}) {
	stackTrace := getStackTrace(2)
	fields["stack_trace"] = stackTrace
	g.logger.Error(message, fields)
}

// Get Stack Trace
func getStackTrace(skip int) string {
	var stackTrace strings.Builder
	for i := skip; ; i++ {
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		funcName := runtime.FuncForPC(pc).Name()
		stackTrace.WriteString(fmt.Sprintf("File: %s, Line: %d, Function: %s\n", file, line, funcName))
	}
	return stackTrace.String()
}
