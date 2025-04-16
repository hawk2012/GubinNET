package main

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type LogLevel int

const (
	Info LogLevel = iota
	Warning
	Error
	Debug
)

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

type Logger struct {
	logFilePath string
	mu          sync.Mutex
}

func NewLogger(logDirectory string) *Logger {
	absLogDir, err := filepath.Abs(logDirectory)
	if err != nil {
		fmt.Println("Invalid log path:", err)
		return nil
	}
	if _, err := os.Stat(absLogDir); os.IsNotExist(err) {
		os.MkdirAll(absLogDir, 0755)
	}
	logFileName := fmt.Sprintf("log_%s.json", time.Now().Format("20060102"))
	logFilePath := filepath.Join(absLogDir, logFileName)
	return &Logger{logFilePath: logFilePath}
}

func (l *Logger) Log(message string, level LogLevel, fields map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	levelStr := levelToString(level)
	logEntry := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"level":     levelStr,
		"message":   message,
	}
	for k, v := range fields {
		logEntry[k] = v
	}
	jsonData, err := json.Marshal(logEntry)
	if err != nil {
		fmt.Println("Error marshaling log entry:", err)
		return
	}
	fmt.Println(string(jsonData))
	file, err := os.OpenFile(l.logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error writing to log:", err)
		return
	}
	defer file.Close()
	file.WriteString(string(jsonData) + "\n")
}

func levelToString(level LogLevel) string {
	switch level {
	case Info:
		return "INFO"
	case Warning:
		return "WARNING"
	case Error:
		return "ERROR"
	case Debug:
		return "DEBUG"
	default:
		return "UNKNOWN"
	}
}

type ConfigParser struct {
	ListenHTTP     int
	ListenHTTPS    int
	ConfigPath     string
	VirtualHosts   map[string]*VirtualHost
	PHPConfig      *PHPSettings
	MaxRequestSize int64
	RequestTimeout time.Duration
	EnableMetrics  bool
	EnableGzip     bool
	TrustedProxies []string
	logger         *Logger
}

type VirtualHost struct {
	Domain         string
	BasePath       string
	WebRootPath    string
	DefaultProxy   string
	InternalPort   int
	SSLCertificate string
	SSLKey         string
	AppMode        string
	DllPath        string
	AppProcess     *os.Process
	SPAFallback    string
	BasicAuth      map[string]string
	CORS           CORSSettings
	RateLimit      int
}

type CORSSettings struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
}

type PHPSettings struct {
	Enabled     bool
	BinaryPath  string
	WebRootPath string
}

func (c *ConfigParser) Load(filePath string) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("config file not found: %s", filePath)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	c.VirtualHosts = make(map[string]*VirtualHost)
	var currentHost *VirtualHost
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := line[1 : len(line)-1]
			if strings.HasPrefix(section, "Host:") {
				hostName := section[len("Host:"):]
				currentHost = &VirtualHost{
					Domain:    hostName,
					BasicAuth: make(map[string]string),
					CORS: CORSSettings{
						AllowedMethods: []string{"GET", "POST", "HEAD"},
					},
				}
				c.VirtualHosts[hostName] = currentHost
				c.logger.Log("Loaded host", Info, map[string]interface{}{"host": hostName})
			} else if section == "PHP" {
				c.PHPConfig = &PHPSettings{}
			}
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if currentHost != nil {
			switch key {
			case "BasePath":
				currentHost.BasePath = value
			case "WebRootPath":
				currentHost.WebRootPath = value
			case "DefaultProxy":
				currentHost.DefaultProxy = value
			case "InternalPort":
				port, err := strconv.Atoi(value)
				if err != nil || port <= 0 || port > 65535 {
					c.logger.Log("Invalid InternalPort", Error, map[string]interface{}{"value": value, "error": err})
					continue
				}
				currentHost.InternalPort = port
			case "SSLCertificate":
				currentHost.SSLCertificate = value
			case "SSLKey":
				currentHost.SSLKey = value
			case "AppMode":
				currentHost.AppMode = value
			case "DllPath":
				currentHost.DllPath = value
			case "SPAFallback":
				currentHost.SPAFallback = value
			case "BasicAuth":
				authParts := strings.SplitN(value, ":", 2)
				if len(authParts) == 2 {
					currentHost.BasicAuth[authParts[0]] = authParts[1]
				}
			case "CORSAllowedOrigins":
				currentHost.CORS.AllowedOrigins = strings.Split(value, ",")
			case "CORSAllowedHeaders":
				currentHost.CORS.AllowedHeaders = strings.Split(value, ",")
			case "RateLimit":
				rateLimit, err := strconv.Atoi(value)
				if err != nil {
					c.logger.Log("Invalid RateLimit", Error, map[string]interface{}{"value": value, "error": err})
					continue
				}
				currentHost.RateLimit = rateLimit
			}
		} else if c.PHPConfig != nil {
			switch key {
			case "Enabled":
				c.PHPConfig.Enabled, _ = strconv.ParseBool(value)
			case "BinaryPath":
				absBinPath, err := filepath.Abs(value)
				if err != nil {
					c.logger.Log("Invalid PHP BinaryPath", Error, map[string]interface{}{"path": value, "error": err})
					continue
				}
				c.PHPConfig.BinaryPath = absBinPath
			case "WebRootPath":
				c.PHPConfig.WebRootPath = value
			}
		} else {
			switch key {
			case "ListenHTTP":
				c.ListenHTTP, _ = strconv.Atoi(value)
			case "ListenHTTPS":
				c.ListenHTTPS, _ = strconv.Atoi(value)
			case "ConfigPath":
				absConfigPath, err := filepath.Abs(value)
				if err != nil {
					c.logger.Log("Invalid ConfigPath", Error, map[string]interface{}{"path": value, "error": err})
					continue
				}
				c.ConfigPath = absConfigPath
			case "MaxRequestSize":
				size, err := strconv.ParseInt(value, 10, 64)
				if err == nil {
					c.MaxRequestSize = size
				}
			case "RequestTimeout":
				timeout, err := time.ParseDuration(value)
				if err == nil {
					c.RequestTimeout = timeout
				}
			case "EnableMetrics":
				c.EnableMetrics, _ = strconv.ParseBool(value)
			case "EnableGzip":
				c.EnableGzip, _ = strconv.ParseBool(value)
			case "TrustedProxies":
				c.TrustedProxies = strings.Split(value, ",")
			}
		}
	}
	return nil
}

type GubinNET struct {
	config    *ConfigParser
	logger    *Logger
	cache     map[string]*cacheEntry
	mu        sync.Mutex
	cookieJar http.CookieJar
}

type cacheEntry struct {
	content     []byte
	modTime     time.Time
	size        int64
	contentType string
}

func (g *GubinNET) Start() {
	g.logger.Log("Starting server", Info, nil)
	g.cache = make(map[string]*cacheEntry)

	// Инициализация cookie jar
	jar, err := cookiejar.New(nil)
	if err != nil {
		g.logger.Log("Failed to initialize cookie jar", Error, map[string]interface{}{"error": err})
	} else {
		g.cookieJar = jar
	}

	for _, host := range g.config.VirtualHosts {
		if host.AppMode == "dotnet" && host.DllPath != "" && host.InternalPort != 0 {
			go func(h *VirtualHost) {
				err := g.startDotNetApp(h)
				if err != nil {
					g.logger.Log("Failed to start .NET app", Error, map[string]interface{}{
						"host":  h.Domain,
						"error": err,
					})
				}
			}(host)
		}
	}
	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", g.config.ListenHTTP),
		Handler:      g.recoveryMiddleware(g.loggingMiddleware(g.metricsMiddleware(g.handleRequest))),
		ReadTimeout:  g.config.RequestTimeout,
		WriteTimeout: g.config.RequestTimeout,
	}
	go func() {
		g.logger.Log("HTTP server started", Info, map[string]interface{}{
			"port": g.config.ListenHTTP,
		})
		err := httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			g.logger.Log("HTTP server error", Error, map[string]interface{}{
				"error": err,
			})
		}
	}()
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host, exists := g.config.VirtualHosts[hello.ServerName]
			if !exists || host.SSLCertificate == "" || host.SSLKey == "" {
				return nil, fmt.Errorf("certificate not found for host: %s", hello.ServerName)
			}
			cert, err := tls.LoadX509KeyPair(host.SSLCertificate, host.SSLKey)
			if err != nil {
				g.logger.Log("Failed to load certificate", Error, map[string]interface{}{
					"host":  hello.ServerName,
					"error": err,
				})
				return nil, err
			}
			return &cert, nil
		},
		NextProtos: []string{"h2", "http/1.1"},
	}
	httpsServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", g.config.ListenHTTPS),
		TLSConfig:    tlsConfig,
		Handler:      g.recoveryMiddleware(g.loggingMiddleware(g.metricsMiddleware(g.handleRequest))),
		ReadTimeout:  g.config.RequestTimeout,
		WriteTimeout: g.config.RequestTimeout,
	}
	go func() {
		g.logger.Log("HTTPS server started", Info, map[string]interface{}{
			"port": g.config.ListenHTTPS,
		})
		err := httpsServer.ListenAndServeTLS("", "")
		if err != nil && err != http.ErrServerClosed {
			g.logger.Log("HTTPS server error", Error, map[string]interface{}{
				"error": err,
			})
		}
	}()
	var metricsServer *http.Server
	if g.config.EnableMetrics {
		go func() {
			metricsMux := http.NewServeMux()
			metricsMux.Handle("/metrics", promhttp.Handler())
			metricsServer = &http.Server{
				Addr:    ":9090",
				Handler: metricsMux,
			}
			g.logger.Log("Metrics server started", Info, map[string]interface{}{
				"port": 9090,
			})
			err := metricsServer.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				g.logger.Log("Metrics server error", Error, map[string]interface{}{
					"error": err,
				})
			}
		}()
	}
	var healthServer *http.Server
	go func() {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		})
		healthServer = &http.Server{
			Addr:    ":8081",
			Handler: healthMux,
		}
		g.logger.Log("Health server started", Info, map[string]interface{}{
			"port": 8081,
		})
		err := healthServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			g.logger.Log("Health server error", Error, map[string]interface{}{
				"error": err,
			})
		}
	}()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGHUP:
				g.logger.Log("Reloading configuration", Info, nil)
				err := g.config.Load(g.config.ConfigPath)
				if err != nil {
					g.logger.Log("Failed to reload config", Error, map[string]interface{}{
						"error": err,
					})
				}
			case os.Interrupt, syscall.SIGTERM:
				g.logger.Log("Shutting down server", Info, nil)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				httpServer.Shutdown(ctx)
				httpsServer.Shutdown(ctx)
				if g.config.EnableMetrics {
					metricsServer.Shutdown(ctx)
				}
				healthServer.Shutdown(ctx)
				for _, host := range g.config.VirtualHosts {
					if host.AppProcess != nil {
						g.logger.Log("Stopping .NET app", Info, map[string]interface{}{
							"host": host.Domain,
							"pid":  host.AppProcess.Pid,
						})
						host.AppProcess.Signal(syscall.SIGTERM)
					}
				}
				g.logger.Log("Server gracefully stopped", Info, nil)
				return
			}
		}
	}()
}

func (g *GubinNET) recoveryMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				g.logger.Log("Recovered from panic", Error, map[string]interface{}{
					"error": err,
					"path":  r.URL.Path,
				})
			}
		}()
		next(w, r)
	}
}

func (g *GubinNET) loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = fmt.Sprintf("%d", time.Now().UnixNano())
		}
		g.logger.Log("Request started", Info, map[string]interface{}{
			"request_id": requestID,
			"method":     r.Method,
			"path":       r.URL.Path,
			"remote":     r.RemoteAddr,
			"user_agent": r.UserAgent(),
		})
		w.Header().Set("X-Request-ID", requestID)
		ww := &responseWriterWrapper{w: w}
		next(ww, r)
		g.logger.Log("Request completed", Info, map[string]interface{}{
			"request_id":  requestID,
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      ww.status,
			"duration_ms": time.Since(start).Milliseconds(),
		})
	}
}

func (g *GubinNET) metricsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		activeConnections.Inc()
		defer activeConnections.Dec()
		ww := &responseWriterWrapper{w: w}
		next(ww, r)
		duration := time.Since(start).Seconds()
		requestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
		requestsTotal.WithLabelValues(r.Method, r.URL.Path, strconv.Itoa(ww.status)).Inc()
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

func (g *GubinNET) startDotNetApp(host *VirtualHost) error {
	cmd := exec.Command("dotnet", host.DllPath)
	cmd.Dir = filepath.Dir(host.DllPath)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("ASPNETCORE_URLS=http://0.0.0.0:%d", host.InternalPort),
		"ASPNETCORE_ENVIRONMENT=Production",
		"DOTNET_PRINT_TELEMETRY_MESSAGE=false",
		"ASPNETCORE_SERVER_HEADER=",
	)
	err := cmd.Start()
	if err != nil {
		return err
	}
	host.AppProcess = cmd.Process
	g.logger.Log("Started .NET app", Info, map[string]interface{}{
		"host": host.Domain,
		"pid":  cmd.Process.Pid,
	})
	return nil
}

func (g *GubinNET) handleRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Del("Server")
	w.Header().Set("Server", "GubinNET/1.1")
	if g.config.MaxRequestSize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, g.config.MaxRequestSize)
	}
	if strings.Contains(r.URL.Path, "../") {
		g.serveErrorPage(w, r, http.StatusBadRequest, "Invalid URL path")
		return
	}
	hostHeader := strings.Split(r.Host, ":")[0]
	host, exists := g.config.VirtualHosts[hostHeader]
	if !exists {
		g.serveErrorPage(w, r, http.StatusNotFound, "Host not found")
		return
	}
	if host.RateLimit > 0 {
		ip := r.RemoteAddr
		if proxyIndex := strings.Index(ip, ","); proxyIndex != -1 {
			ip = ip[:proxyIndex]
		}
		ip = strings.TrimSpace(strings.Split(ip, ":")[0])
		clientKey := ip + ":" + host.Domain
		rateLimiterLock.Lock()
		if _, exists := rateLimiter[clientKey]; !exists {
			rateLimiter[clientKey] = time.Now()
		} else {
			if time.Since(rateLimiter[clientKey]) < time.Second/time.Duration(host.RateLimit) {
				g.serveErrorPage(w, r, http.StatusTooManyRequests, "Rate limit exceeded")
				rateLimiterLock.Unlock()
				return
			}
			rateLimiter[clientKey] = time.Now()
		}
		rateLimiterLock.Unlock()
	}
	if len(host.BasicAuth) > 0 {
		username, password, ok := r.BasicAuth()
		if !ok || host.BasicAuth[username] != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			g.serveErrorPage(w, r, http.StatusUnauthorized, "Unauthorized")
			return
		}
	}
	if len(host.CORS.AllowedOrigins) > 0 {
		origin := r.Header.Get("Origin")
		if origin != "" {
			for _, allowed := range host.CORS.AllowedOrigins {
				if allowed == "*" || allowed == origin {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					if r.Method == "OPTIONS" {
						w.Header().Set("Access-Control-Allow-Methods", strings.Join(host.CORS.AllowedMethods, ","))
						if len(host.CORS.AllowedHeaders) > 0 {
							w.Header().Set("Access-Control-Allow-Headers", strings.Join(host.CORS.AllowedHeaders, ","))
						}
						w.WriteHeader(http.StatusNoContent)
						return
					}
					break
				}
			}
		}
	}
	if host.DefaultProxy != "" || (host.AppMode == "dotnet" && host.InternalPort != 0) {
		var proxyUrl string
		if host.DefaultProxy != "" {
			proxyUrl = host.DefaultProxy
		} else {
			proxyUrl = fmt.Sprintf("http://127.0.0.1:%d", host.InternalPort)
		}
		g.proxyRequest(w, r, proxyUrl)
		return
	}
	g.serveFileOrSpa(w, r, host)
}

func (g *GubinNET) proxyRequest(w http.ResponseWriter, r *http.Request, proxyUrl string) {
	client := &http.Client{
		Timeout: g.config.RequestTimeout,
		Transport: &http.Transport{
			ResponseHeaderTimeout: g.config.RequestTimeout / 2,
		},
		Jar: g.cookieJar,
	}
	req, err := http.NewRequest(r.Method, proxyUrl+r.URL.RequestURI(), r.Body)
	if err != nil {
		g.serveErrorPage(w, r, http.StatusBadGateway, "Proxy error")
		r.Body.Close()
		return
	}
	defer req.Body.Close()

	// Передача всех заголовков
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Добавляем реальный IP адрес
	req.Header.Set("X-Real-IP", getRealIP(r))
	req.Header.Set("X-Forwarded-For", getRealIP(r))

	resp, err := client.Do(req)
	if err != nil {
		g.serveErrorPage(w, r, http.StatusBadGateway, "Proxy error")
		return
	}
	defer resp.Body.Close()

	// Специальная обработка Set-Cookie
	for key, values := range resp.Header {
		if key == "Set-Cookie" {
			w.Header()["Set-Cookie"] = values
		} else {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (g *GubinNET) serveFileOrSpa(w http.ResponseWriter, r *http.Request, host *VirtualHost) {
	webRootPath := host.WebRootPath
	if webRootPath == "" {
		webRootPath = host.BasePath
	}
	requestPath := filepath.Clean(strings.TrimLeft(r.URL.Path, "/"))
	fullPath := filepath.Join(webRootPath, requestPath)
	fileInfo, err := os.Stat(fullPath)
	if err == nil && !fileInfo.IsDir() {
		g.serveFile(w, r, fullPath, fileInfo)
		return
	}
	if host.SPAFallback != "" {
		spaPath := filepath.Join(webRootPath, host.SPAFallback)
		if _, err := os.Stat(spaPath); err == nil {
			g.serveFile(w, r, spaPath, nil)
			return
		}
	}
	g.serveErrorPage(w, r, http.StatusNotFound, "File Not Found")
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
		if fileInfo.Size() > g.config.MaxRequestSize {
			g.serveErrorPage(w, r, http.StatusRequestEntityTooLarge, "File too large")
			return
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
	if g.config.EnableGzip && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		gz.Write(cached.content)
	} else {
		w.Write(cached.content)
	}
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
	case ".svg":
		return "image/svg+xml"
	case ".webp":
		return "image/webp"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ttf":
		return "font/ttf"
	case ".eot":
		return "application/vnd.ms-fontobject"
	case ".otf":
		return "font/otf"
	case ".xml":
		return "application/xml"
	case ".pdf":
		return "application/pdf"
	case ".zip":
		return "application/zip"
	case ".txt":
		return "text/plain; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

func (g *GubinNET) serveErrorPage(w http.ResponseWriter, r *http.Request, statusCode int, message string) {
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
    <p>Server: GubinNET/1.1</p>
    <p>Request ID: %s</p>
</body>
</html>
`, statusCode, statusCode, message, w.Header().Get("X-Request-ID"))
	w.Write([]byte(html))
}

var (
	rateLimiter     = make(map[string]time.Time)
	rateLimiterLock sync.Mutex
)

func getRealIP(r *http.Request) string {
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip = strings.Split(r.RemoteAddr, ":")[0]
	}
	return ip
}

func main() {
	logger := NewLogger("/etc/gubinnet/logs")
	if logger == nil {
		fmt.Println("Failed to initialize logger")
		os.Exit(1)
	}
	config := &ConfigParser{
		logger:         logger,
		MaxRequestSize: 10 << 20, // 10MB default
		RequestTimeout: 30 * time.Second,
		EnableMetrics:  true,
		EnableGzip:     true,
	}
	configPath := os.Getenv("GUBINNET_CONFIG")
	if configPath == "" {
		configPath = "/etc/gubinnet/config.ini"
	}
	err := config.Load(configPath)
	if err != nil {
		logger.Log("Failed to load config", Error, map[string]interface{}{
			"error": err,
			"path":  configPath,
		})
		os.Exit(1)
	}
	server := &GubinNET{
		config: config,
		logger: logger,
	}
	server.Start()
	select {}
}
