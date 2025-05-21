package main

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef char* (*process_func)(const char*);

void* load_library(const char* path) {
    return dlopen(path, RTLD_LAZY);
}

process_func get_process_function(void* handle) {
    return (process_func)dlsym(handle, "process");
}

char* call_process(process_func fn, const char* input) {
    if (!fn) return NULL;
    return fn(input);
}

void free_library(void* handle) {
    dlclose(handle);
}
*/
import "C"
import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Константы
const (
	ConfigDir          = "/etc/gubinnet/config"
	LogDir             = "/etc/gubinnet/logs"
	ModulesDir         = "/etc/gubinnet/modules"
	DefaultModuleIndex = "module.cpp"
)

// Prometheus метрики
var (
	requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Всего HTTP-запросов",
	}, []string{"method", "path", "status"})
	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "Длительность HTTP-запросов",
		Buckets: []float64{0.1, 0.5, 1, 2.5, 5, 10},
	}, []string{"method", "path"})
	activeConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "http_active_connections",
		Help: "Активные соединения",
	})
	moduleExecutions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "module_executions_total",
		Help: "Вызовы модулей",
	}, []string{"language", "name"})
	moduleErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "module_errors_total",
		Help: "Ошибки при выполнении модулей",
	}, []string{"language", "name"})
)

// Виртуальный хост
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

// Сервер
type GubinNET struct {
	config       *ConfigParser
	logger       *Logger
	cache        map[string]*cacheEntry
	mu           sync.Mutex
	antiDDoS     *AntiDDoS
	servers      map[string]*http.Server
	moduleLogger *ModuleLogger
	modules      map[string]Module // фоновые модули
	moduleWG     sync.WaitGroup
}

type cacheEntry struct {
	content     []byte
	modTime     time.Time
	size        int64
	contentType string
}

// Парсер конфигурации
type ConfigParser struct {
	VirtualHosts map[string]*VirtualHost
}

// Логгер
type Logger struct {
	file  *os.File
	jsonb bool
	mu    sync.Mutex
}

func NewLogger(logDir string, jsonb bool) *Logger {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil
	}
	logFile := filepath.Join(logDir, "access.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil
	}
	return &Logger{file: f, jsonb: jsonb}
}

func (l *Logger) Info(msg string, fields map[string]interface{}) {
	l.log("INFO", msg, fields)
}

func (l *Logger) Warning(msg string, fields map[string]interface{}) {
	l.log("WARNING", msg, fields)
}

func (l *Logger) Error(msg string, fields map[string]interface{}) {
	l.log("ERROR", msg, fields)
}

func (l *Logger) log(level, msg string, fields map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	timestamp := time.Now().Format(time.RFC3339)
	if l.jsonb {
		fieldsStr := "{"
		for k, v := range fields {
			fieldsStr += fmt.Sprintf(`"%s":%q,`, k, v)
		}
		if len(fieldsStr) > 0 && strings.HasSuffix(fieldsStr, ",") {
			fieldsStr = fieldsStr[:len(fieldsStr)-1]
		}
		fieldsStr += "}"
		line := fmt.Sprintf("%s [%s] %s %s\n", timestamp, level, msg, fieldsStr)
		l.file.WriteString(line)
	} else {
		fieldsStr := ""
		for k, v := range fields {
			fieldsStr += fmt.Sprintf(" %s=\"%v\"", k, v)
		}
		line := fmt.Sprintf("%s [%s]%s %s\n", timestamp, level, fieldsStr, msg)
		l.file.WriteString(line)
	}
}

func (l *Logger) Close() {
	_ = l.file.Close()
}

func (l *Logger) StartAutoRotate() {
	go func() {
		for {
			time.Sleep(24 * time.Hour)
			newFile, err := os.OpenFile(filepath.Join(LogDir, "access.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				l.mu.Lock()
				_ = l.file.Close()
				l.file = newFile
				l.mu.Unlock()
			}
		}
	}()
}

// Логгер для модулей
type ModuleLogger struct {
	logger *log.Logger
}

func NewModuleLogger() *ModuleLogger {
	return &ModuleLogger{
		logger: log.New(os.Stdout, "[MODULE] ", log.LstdFlags),
	}
}

func (ml *ModuleLogger) Log(moduleName, message string) {
	ml.logger.Printf("[%s] %s", moduleName, message)
}

// Анти-DDoS
type AntiDDoSConfig struct {
	MaxRequestsPerSecond int
	BlockDuration        time.Duration
	LogFilePath          string
}

type AntiDDoS struct {
	cfg       *AntiDDoSConfig
	ipCount   map[string]int
	timestamp time.Time
	bannedIPs map[string]time.Time
	mu        sync.Mutex
	logFile   *os.File
}

func NewAntiDDoS(cfg *AntiDDoSConfig) (*AntiDDoS, error) {
	if cfg.LogFilePath == "" {
		cfg.LogFilePath = "/tmp/antiddos.log"
	}
	logFile, err := os.OpenFile(cfg.LogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &AntiDDoS{
		cfg:       cfg,
		ipCount:   make(map[string]int),
		timestamp: time.Now(),
		bannedIPs: make(map[string]time.Time),
		logFile:   logFile,
	}, nil
}

func (a *AntiDDoS) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getRealIP(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		now := time.Now()

		for ip, banTime := range a.bannedIPs {
			if now.Sub(banTime) > a.cfg.BlockDuration {
				delete(a.bannedIPs, ip)
			}
		}

		if _, banned := a.bannedIPs[ip]; banned {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			a.logToFile(fmt.Sprintf("Blocked IP due to DDoS protection: %s", ip))
			return
		}

		if now.Sub(a.timestamp) > time.Second {
			a.ipCount = make(map[string]int)
			a.timestamp = now
		}

		a.ipCount[ip]++
		if a.ipCount[ip] > a.cfg.MaxRequestsPerSecond {
			a.bannedIPs[ip] = now
			http.Error(w, "403 Too many requests", http.StatusForbidden)
			a.logToFile(fmt.Sprintf("Banned IP due to DDoS protection: %s", ip))
			return
		}

		next(w, r)
	}
}

func (a *AntiDDoS) logToFile(msg string) {
	_, _ = a.logFile.WriteString(time.Now().Format(time.RFC3339) + " [ANTIDDOS] " + msg + "\n")
}

func (a *AntiDDoS) Close() {
	_ = a.logFile.Close()
}

// Тип модуля
type Module interface {
	Start()
	Stop()
	Process(input string) string
}

// CGO модуль
type CGOModule struct {
	Name     string
	Path     string
	handle   unsafe.Pointer
	fn       C.process_func
	running  bool
	logger   *ModuleLogger
	interval time.Duration
}

func NewCGOModule(name, path string, logger *ModuleLogger, interval time.Duration) *CGOModule {
	return &CGOModule{
		Name:     name,
		Path:     path,
		logger:   logger,
		interval: interval,
	}
}

func (m *CGOModule) Start() {
	m.running = true
	m.logger.Log(m.Name, "Starting background module")

	module := C.load_library(C.CString(m.Path))
	if module == nil {
		moduleErrors.WithLabelValues("cgo", m.Name).Inc()
		m.logger.Log(m.Name, "Failed to load module")
		return
	}
	m.handle = module

	processFn := C.get_process_function(module)
	if processFn == nil {
		moduleErrors.WithLabelValues("cgo", m.Name).Inc()
		m.logger.Log(m.Name, "Function 'process' not found")
		return
	}
	m.fn = processFn

	go func() {
		for m.running {
			result := C.call_process(m.fn, C.CString("background"))
			if result != nil {
				output := C.GoString(result)
				m.logger.Log(m.Name, output)
				moduleExecutions.WithLabelValues("cgo", m.Name).Inc()
				C.free(unsafe.Pointer(result))
			}
			time.Sleep(m.interval)
		}
	}()
}

func (m *CGOModule) Stop() {
	m.running = false
	if m.handle != nil {
		C.free_library(m.handle)
	}
}

func (m *CGOModule) Process(input string) string {
	if !m.running || m.fn == nil {
		return "Module is not running"
	}
	cInput := C.CString(input)
	defer C.free(unsafe.Pointer(cInput))

	result := C.call_process(m.fn, cInput)
	if result == nil {
		moduleErrors.WithLabelValues("cgo", m.Name).Inc()
		return "Module returned NULL"
	}

	output := C.GoString(result)
	moduleExecutions.WithLabelValues("cgo", m.Name).Inc()
	C.free(unsafe.Pointer(result))
	return output
}

// Загрузка модулей
func (g *GubinNET) startBackgroundModules() {
	files, err := os.ReadDir(ModulesDir)
	if err != nil {
		g.logger.Warning("No modules directory found", map[string]interface{}{"error": err})
		return
	}

	for _, file := range files {
		if file.IsDir() {
			moduleDir := filepath.Join(ModulesDir, file.Name())
			moduleSo := filepath.Join(moduleDir, "module.so")
			if _, err := os.Stat(moduleSo); err == nil {
				module := NewCGOModule(file.Name(), moduleSo, g.moduleLogger, 10*time.Second)
				module.Start()
				g.modules[file.Name()] = module
			}
		}
	}
}

func (g *GubinNET) gracefulShutdown() {
	var wg sync.WaitGroup
	for serverName, server := range g.servers {
		wg.Add(1)
		go func(name string, srv *http.Server) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			server.Shutdown(ctx)
		}(serverName, server)
	}
	wg.Wait()

	// Остановить фоновые модули
	for _, module := range g.modules {
		module.Stop()
	}
}

func (g *GubinNET) applyNewConfig(newConfig *ConfigParser) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for serverName, newHost := range newConfig.VirtualHosts {
		if existingHost, exists := g.config.VirtualHosts[serverName]; exists {
			existingHost.ServerName = newHost.ServerName
			existingHost.ListenPort = newHost.ListenPort
			existingHost.Root = newHost.Root
			existingHost.Index = newHost.Index
			existingHost.TryFiles = newHost.TryFiles
			existingHost.UseSSL = newHost.UseSSL
			existingHost.CertPath = newHost.CertPath
			existingHost.KeyPath = newHost.KeyPath
			existingHost.RedirectToHTTPS = newHost.RedirectToHTTPS
			existingHost.ProxyURL = newHost.ProxyURL
		} else {
			g.config.VirtualHosts[serverName] = newHost
			g.startVirtualHost(newHost)
		}
	}
	for serverName := range g.config.VirtualHosts {
		if _, exists := newConfig.VirtualHosts[serverName]; !exists {
			g.stopVirtualHost(serverName)
			delete(g.config.VirtualHosts, serverName)
		}
	}
}

func (g *GubinNET) Start() {
	g.logger.Info("Starting server", nil)
	g.startBackgroundModules()

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
			g.logger.Warning("No certificate found for host", map[string]interface{}{
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

func (g *GubinNET) startVirtualHost(host *VirtualHost) {
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", host.ListenPort),
		Handler:      g.setupMiddleware(http.HandlerFunc(g.handleRequest)),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	if host.UseSSL {
		cert, err := tls.LoadX509KeyPair(host.CertPath, host.KeyPath)
		if err == nil {
			server.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}
		}
	}
	g.mu.Lock()
	g.servers[host.ServerName] = server
	g.mu.Unlock()
	go func() {
		var err error
		if host.UseSSL {
			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			g.logger.Error("Server error", map[string]interface{}{
				"server_name": host.ServerName,
				"error":       err,
			})
		}
	}()
}

func (g *GubinNET) stopVirtualHost(serverName string) {
	g.mu.Lock()
	server, exists := g.servers[serverName]
	if exists {
		delete(g.servers, serverName)
	}
	g.mu.Unlock()
	if exists {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}
}

func (g *GubinNET) handleRequest(w http.ResponseWriter, r *http.Request) {
	defer func(start time.Time) {
		duration := time.Since(start).Seconds()
		requestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
	}(time.Now())

	requestID := uuid.New().String()
	w.Header().Set("X-Request-ID", requestID)
	hostHeader := strings.Split(strings.TrimSuffix(r.Host, ";"), ":")[0]
	host, exists := g.config.VirtualHosts[hostHeader]
	if !exists || host.Root == "" {
		g.serveHostNotFoundPage(w, r, requestID)
		return
	}

	if host.RedirectToHTTPS && r.TLS == nil {
		url := "https://" + hostHeader + r.URL.String()
		http.Redirect(w, r, url, http.StatusPermanentRedirect)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/modules/") {
		moduleName := strings.TrimPrefix(r.URL.Path, "/modules/")
		moduleDir := filepath.Join(ModulesDir, moduleName)
		moduleSo := filepath.Join(moduleDir, "module.so")
		indexCpp := filepath.Join(moduleDir, DefaultModuleIndex)

		if _, err := os.Stat(moduleDir); os.IsNotExist(err) {
			g.serveErrorPage(w, r, http.StatusNotFound, "Module Not Found", "", requestID)
			return
		}

		if _, err := os.Stat(moduleSo); os.IsNotExist(err) {
			if _, err := os.Stat(indexCpp); os.IsNotExist(err) {
				g.serveErrorPage(w, r, http.StatusNotFound, "Module Index File Not Found", "", requestID)
				return
			}
			if err := compileCppModule(moduleDir, indexCpp); err != nil {
				g.serveErrorPage(w, r, http.StatusInternalServerError, "Compilation Failed", err.Error(), requestID)
				return
			}
		}

		module, exists := g.modules[moduleName]
		if !exists {
			module = NewCGOModule(moduleName, moduleSo, g.moduleLogger, 10*time.Second)
			module.Start()
			g.modules[moduleName] = module
		}

		input := r.URL.Query().Get("input")
		output := module.Process(input)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, output)
		return
	}

	g.serveFileOrSpa(w, r, host, requestID)
}

func compileCppModule(moduleDir, sourcePath string) error {
	tempDir, err := os.MkdirTemp("", "cppmod-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	cmd := exec.Command("cp", "-r", moduleDir+"/.", tempDir)
	if err := cmd.Run(); err != nil {
		return err
	}

	objectPath := filepath.Join(tempDir, "module.so")
	cmd = exec.Command("g++", "-shared", "-fPIC", "module.cpp", "-o", objectPath)
	cmd.Dir = tempDir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("compilation failed: %v - %s", err, stderr.String())
	}

	targetSo := filepath.Join(moduleDir, "module.so")
	os.Remove(targetSo)
	return os.Rename(objectPath, targetSo)
}

func findModuleBinary(dir string) (string, error) {
	for _, ext := range []string{".so", ".dylib", ".dll"} {
		path := filepath.Join(dir, "module"+ext)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no module binary found")
}

func getRealIP(r *http.Request) string {
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip = strings.Split(r.RemoteAddr, ":")[0]
	}
	return ip
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

func (g *GubinNET) serveFileOrSpa(w http.ResponseWriter, r *http.Request, host *VirtualHost, requestID string) {
	webRootPath := host.Root
	if webRootPath == "" {
		g.serveErrorPage(w, r, http.StatusInternalServerError, "Server configuration error", "", requestID)
		return
	}
	requestPath := filepath.Clean(strings.TrimLeft(r.URL.Path, "/"))
	fullPath := filepath.Join(webRootPath, requestPath)
	fileInfo, err := os.Stat(fullPath)

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

	if host.ProxyURL != "" {
		g.handleProxy(w, r, host.ProxyURL, requestID)
		return
	}

	g.serveErrorPage(w, r, http.StatusNotFound, "File Not Found", fmt.Sprintf("File '%s' does not exist in root path '%s'", requestPath, webRootPath), requestID)
}

func (g *GubinNET) handleProxy(w http.ResponseWriter, r *http.Request, proxyURL string, requestID string) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequest(r.Method, proxyURL+r.URL.String(), r.Body)
	if err != nil {
		g.serveErrorPage(w, r, http.StatusInternalServerError, "Internal Server Error", "", requestID)
		return
	}
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		g.serveErrorPage(w, r, http.StatusBadGateway, "Bad Gateway", "", requestID)
		return
	}
	defer resp.Body.Close()
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (g *GubinNET) securityMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.ToLower(r.URL.Path)
		re := regexp.MustCompile(`(\.\./|%2e%2e|\.env|phpmyadmin|shell|setup-config.php|device\.rsp)`)
		if re.MatchString(path) {
			ip := getRealIP(r)
			g.logger.Warning("Blocked suspicious request", map[string]interface{}{
				"path":       path,
				"ip":         ip,
				"request_id": w.Header().Get("X-Request-ID"),
			})
			g.serveErrorPage(w, r, http.StatusForbidden, "Access Denied", "", w.Header().Get("X-Request-ID"))
			return
		}
		next(w, r)
	}
}

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

func (g *GubinNET) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		activeConnections.Inc()
		defer activeConnections.Dec()
		next.ServeHTTP(w, r)
	})
}

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
				g.serveErrorPage(w, r, http.StatusInternalServerError, "Internal Server Error", "", requestID)
				return
			}
		}
		content, err := os.ReadFile(filePath)
		if err != nil {
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

func (g *GubinNET) serveErrorPage(w http.ResponseWriter, r *http.Request, statusCode int, message string, details string, requestID string) {
	g.logger.Error("Error page served", map[string]interface{}{
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
    <p>Server: GubinNET/1.5.1</p>
    <p>Request ID: %s</p>
</body>
</html>
`, statusCode, statusCode, message, details, requestID)
	w.Write([]byte(html))
}

func (g *GubinNET) serveHostNotFoundPage(w http.ResponseWriter, r *http.Request, requestID string) {
	g.logger.Error("Host not found page served", map[string]interface{}{
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
    <p>Server: GubinNET/1.5.1</p>
</body>
</html>
`
	w.Write([]byte(html))
}

// responseWriterWrapper для захвата статус-кода
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

// Загрузка конфигурации
func loadConfiguration(configDir string, logger *Logger) *ConfigParser {
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
				logger.Warning("Failed to parse virtual host configuration", map[string]interface{}{
					"file":  file.Name(),
					"error": err,
				})
				continue
			}
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

// Парсинг INI файла
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

// Main function
func main() {
	logger := NewLogger(LogDir, true)
	if logger == nil {
		fmt.Println("Failed to initialize logger")
		os.Exit(1)
	}
	logger.StartAutoRotate()
	defer logger.Close()

	config := loadConfiguration(ConfigDir, logger)
	if config == nil {
		logger.Error("Failed to load configuration", nil)
		os.Exit(1)
	}

	defaultConfig := &AntiDDoSConfig{
		MaxRequestsPerSecond: 100,
		BlockDuration:        60 * time.Second,
		LogFilePath:          filepath.Join(LogDir, "antiddos.log"),
	}
	antiDDoS, err := NewAntiDDoS(defaultConfig)
	if err != nil {
		logger.Error("Failed to initialize AntiDDoS", map[string]interface{}{"error": err})
		os.Exit(1)
	}
	defer antiDDoS.Close()

	server := &GubinNET{
		config:       config,
		logger:       logger,
		cache:        make(map[string]*cacheEntry),
		antiDDoS:     antiDDoS,
		servers:      make(map[string]*http.Server),
		moduleLogger: NewModuleLogger(),
		modules:      make(map[string]Module),
	}

	server.Start()
	logger.Info("Server started successfully", nil)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	for sig := range sigChan {
		switch sig {
		case syscall.SIGHUP:
			logger.Info("Reloading configuration", nil)
			newConfig := loadConfiguration(ConfigDir, logger)
			if newConfig != nil {
				server.applyNewConfig(newConfig)
				logger.Info("Configuration reloaded successfully", nil)
			} else {
				logger.Error("Failed to reload configuration", nil)
			}
		case os.Interrupt, syscall.SIGTERM:
			logger.Info("Shutting down server", nil)
			server.gracefulShutdown()
			os.Exit(0)
		}
	}
}
