package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// LogLevel defines logging levels
type LogLevel int

const (
	Info LogLevel = iota
	Warning
	Error
	Debug
)

// Logger handles logging functionality
type Logger struct {
	logFilePath string
}

// NewLogger creates a new logger instance
func NewLogger(logDirectory string) *Logger {
	if _, err := os.Stat(logDirectory); os.IsNotExist(err) {
		os.MkdirAll(logDirectory, 0755)
	}
	logFileName := fmt.Sprintf("log_%s.txt", time.Now().Format("20060102"))
	logFilePath := filepath.Join(logDirectory, logFileName)
	return &Logger{logFilePath: logFilePath}
}

// Log writes a message to the log file and console
func (l *Logger) Log(message string, level LogLevel) {
	logEntry := fmt.Sprintf("[%s] [%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), levelToString(level), message)
	fmt.Print(logEntry)
	file, err := os.OpenFile(l.logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Ошибка записи в лог:", err)
		return
	}
	defer file.Close()
	_, _ = file.WriteString(logEntry)
}

// Helper function to convert log level to string
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

// ConfigParser handles configuration parsing
type ConfigParser struct {
	ListenHTTP   int
	ListenHTTPS  int
	ConfigPath   string
	VirtualHosts map[string]*VirtualHost
}

// VirtualHost represents a virtual host configuration
type VirtualHost struct {
	Domain         string
	BasePath       string
	WebRootPath    string
	SSLCertificate string
	SSLKey         string
	AutoSSL        bool
	DefaultProxy   string
	DllPaths       []string
	InternalPort   int // Новый параметр для внутреннего порта
}

// Load reads and parses the configuration file
func (c *ConfigParser) Load(filePath string) error {
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
				currentHost = &VirtualHost{Domain: hostName}
				c.VirtualHosts[hostName] = currentHost
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
			case "SSLCertificate":
				currentHost.SSLCertificate = value
			case "SSLKey":
				currentHost.SSLKey = value
			case "AutoSSL":
				currentHost.AutoSSL, _ = strconv.ParseBool(value)
			case "DefaultProxy":
				currentHost.DefaultProxy = value
			case "DllPaths":
				currentHost.DllPaths = strings.Split(value, ",")
			case "InternalPort":
				currentHost.InternalPort, _ = strconv.Atoi(value)
			}
		} else {
			switch key {
			case "ListenHTTP":
				c.ListenHTTP, _ = strconv.Atoi(value)
			case "ListenHTTPS":
				c.ListenHTTPS, _ = strconv.Atoi(value)
			case "ConfigPath":
				c.ConfigPath = value
				if strings.HasPrefix(c.ConfigPath, "~") {
					homeDir, _ := os.UserHomeDir()
					c.ConfigPath = strings.Replace(c.ConfigPath, "~", homeDir, 1)
				}
			}
		}
	}
	return nil
}

// MyUser implements registration.User interface
type MyUser struct {
	Key          *rsa.PrivateKey
	Registration *registration.Resource
}

func (u *MyUser) GetEmail() string {
	return ""
}

func (u *MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

// SSLManager handles SSL certificate management
type SSLManager struct {
	basePath string
	logger   *Logger
}

// NewSSLManager creates a new SSLManager instance
func NewSSLManager(basePath string, logger *Logger) *SSLManager {
	sslPath := filepath.Join(basePath, "ssl")
	if _, err := os.Stat(sslPath); os.IsNotExist(err) {
		os.MkdirAll(sslPath, 0755)
	}
	return &SSLManager{basePath: sslPath, logger: logger}
}

// obtainCertificate obtains a certificate for the given domain
func (s *SSLManager) obtainCertificate(domain string) (string, string, error) {
	accountKeyPath := filepath.Join(s.basePath, "../account.key")
	certPath := filepath.Join(s.basePath, fmt.Sprintf("%s.pem", domain))
	keyPath := filepath.Join(s.basePath, fmt.Sprintf("%s-key.pem", domain))
	if s.isCertificateValid(certPath, keyPath) {
		s.logger.Log(fmt.Sprintf("Используем существующий сертификат для %s.", domain), Info)
		return certPath, keyPath, nil
	}
	var privateKey *rsa.PrivateKey
	if _, err := os.Stat(accountKeyPath); err == nil {
		privateKeyBytes, err := os.ReadFile(accountKeyPath)
		if err != nil {
			return "", "", fmt.Errorf("ошибка чтения аккаунтного ключа: %w", err)
		}
		privateKey, err = parsePEMPrivateKey(privateKeyBytes)
		if err != nil {
			return "", "", fmt.Errorf("ошибка парсинга аккаунтного ключа: %w", err)
		}
	} else {
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", "", fmt.Errorf("ошибка генерации нового аккаунтного ключа: %w", err)
		}
		privateKeyBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		})
		if err := os.WriteFile(accountKeyPath, privateKeyBytes, 0644); err != nil {
			return "", "", fmt.Errorf("ошибка записи аккаунтного ключа: %w", err)
		}
	}
	user := &MyUser{Key: privateKey}
	config := lego.NewConfig(user)
	config.CADirURL = "https://acme-v02.api.letsencrypt.org/directory"
	config.Certificate.KeyType = certcrypto.RSA2048
	client, err := lego.NewClient(config)
	if err != nil {
		return "", "", fmt.Errorf("ошибка создания клиента lego: %w", err)
	}
	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", ""))
	if err != nil {
		return "", "", fmt.Errorf("ошибка настройки http-01 провайдера: %w", err)
	}
	if user.Registration == nil {
		regOptions := registration.RegisterOptions{TermsOfServiceAgreed: true}
		reg, err := client.Registration.Register(regOptions)
		if err != nil {
			return "", "", fmt.Errorf("ошибка регистрации аккаунта: %w", err)
		}
		user.Registration = reg
	}
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	certs, err := client.Certificate.Obtain(request)
	if err != nil {
		return "", "", fmt.Errorf("ошибка получения сертификата: %w", err)
	}
	if err := os.WriteFile(certPath, certs.Certificate, 0644); err != nil {
		return "", "", fmt.Errorf("ошибка записи сертификата: %w", err)
	}
	if err := os.WriteFile(keyPath, certs.PrivateKey, 0644); err != nil {
		return "", "", fmt.Errorf("ошибка записи приватного ключа: %w", err)
	}
	return certPath, keyPath, nil
}

// isCertificateValid checks if the certificate is valid
func (s *SSLManager) isCertificateValid(certPath, keyPath string) bool {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return false
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return false
	}
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter.Add(-30*24*time.Hour)) {
		return false
	}
	return true
}

// Helper function to parse PEM private key
func parsePEMPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("неверный формат PEM ключа")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// ChildProcessManager manages child processes
type ChildProcessManager struct {
	processes map[string]*exec.Cmd
	mutex     sync.Mutex
	logger    *Logger
	gubinNet  *GubinNET // Ссылка на GubinNET для доступа к конфигурации
}

func NewChildProcessManager(logger *Logger, gubinNet *GubinNET) *ChildProcessManager {
	return &ChildProcessManager{
		processes: make(map[string]*exec.Cmd),
		logger:    logger,
		gubinNet:  gubinNet,
	}
}

func (m *ChildProcessManager) StartProcess(dllPath string, internalPort int, env string, logger *Logger) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if isPortInUse(internalPort) {
		logger.Log(fmt.Sprintf("Порт %d уже занят, пытаемся найти новый...", internalPort), Warning)
		internalPort = findFreePort(internalPort + 1)
	}
	if _, exists := m.processes[dllPath]; exists {
		logger.Log(fmt.Sprintf("Процесс для %s уже запущен", dllPath), Warning)
		return
	}

	logDir := "/etc/gubinnet/logs/dotnet"
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		if err := os.MkdirAll(logDir, 0755); err != nil {
			logger.Log(fmt.Sprintf("Ошибка создания директории для логов: %v", err), Error)
			return
		}
	}

	logFileName := strings.Replace(filepath.Base(dllPath), ".dll", fmt.Sprintf("_%s.log", env), 1)
	logFilePath := filepath.Join(logDir, logFileName)
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		logger.Log(fmt.Sprintf("Ошибка создания лог-файла для %s: %v", dllPath, err), Error)
		return
	}

	cmd := exec.Command("dotnet", dllPath, fmt.Sprintf("--urls=http://127.0.0.1:%d/", internalPort), fmt.Sprintf("--environment=%s", env))
	cmd.Stdout = io.MultiWriter(logFile, os.Stdout)
	cmd.Stderr = io.MultiWriter(logFile, os.Stderr)

	if err := cmd.Start(); err != nil {
		logger.Log(fmt.Sprintf("Ошибка при запуске DLL (%s): %v", dllPath, err), Error)
		logFile.Close()
		return
	}

	m.processes[dllPath] = cmd
	logger.Log(fmt.Sprintf("Запущена DLL: %s на порту %d в режиме %s", dllPath, internalPort, env), Info)

	go func() {
		cmd.Wait()
		logFile.Close()
		logger.Log(fmt.Sprintf("DLL процесс завершился: %s", dllPath), Info)
		m.mutex.Lock()
		delete(m.processes, dllPath)
		m.mutex.Unlock()
	}()
}

// RunHealthChecks performs periodic health checks
func (m *ChildProcessManager) RunHealthChecks(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.mutex.Lock()
			for dllPath, cmd := range m.processes {
				if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
					m.logger.Log(fmt.Sprintf("Обнаружен остановленный процесс: %s. Перезапуск...", dllPath), Warning)

					port, env, found := m.gubinNet.GetDllInfo(dllPath)
					if found {
						delete(m.processes, dllPath)
						go m.StartProcess(dllPath, port, env, m.logger)
					} else {
						m.logger.Log(fmt.Sprintf("Не удалось найти информацию о DLL: %s", dllPath), Error)
					}
				}
			}
			m.mutex.Unlock()
		}
	}
}

// Helper functions to check port availability
func isPortInUse(port int) bool {
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func findFreePort(startPort int) int {
	for port := startPort; port < 65535; port++ {
		if !isPortInUse(port) {
			return port
		}
	}
	return -1
}

// GubinNET represents the main server structure
type GubinNET struct {
	config          *ConfigParser
	logger          *Logger
	childProcessMgr *ChildProcessManager
	sslManager      *SSLManager
	cache           map[string][]byte
	cacheMutex      sync.Mutex
}

// GetDllInfo retrieves the port and environment for a given DLL path
func (g *GubinNET) GetDllInfo(dllPath string) (int, string, bool) {
	for _, host := range g.config.VirtualHosts {
		for _, path := range host.DllPaths {
			if path == dllPath {
				env := "Production"
				if strings.Contains(strings.ToLower(host.Domain), "dev") {
					env = "Development"
				}
				return host.InternalPort, env, true
			}
		}
	}
	return 0, "", false
}

// Start starts the HTTP and HTTPS servers
func (g *GubinNET) Start() {
	g.childProcessMgr = NewChildProcessManager(g.logger, g)
	g.sslManager = NewSSLManager("/etc/gubinnet", g.logger)
	g.cache = make(map[string][]byte)

	for _, host := range g.config.VirtualHosts {
		if len(host.DllPaths) > 0 && host.InternalPort > 0 {
			env := "Production"
			if strings.Contains(strings.ToLower(host.Domain), "dev") {
				env = "Development"
			}
			for _, dllPath := range host.DllPaths {
				if _, err := os.Stat(dllPath); os.IsNotExist(err) {
					g.logger.Log(fmt.Sprintf("DLL-файл не найден: %s", dllPath), Error)
					continue
				}
				g.childProcessMgr.StartProcess(dllPath, host.InternalPort, env, g.logger)
			}
		}
	}

	http.HandleFunc("/", g.handleRequest)
	g.logger.Log(fmt.Sprintf("Сервер запущен на портах %d (HTTP) и %d (HTTPS).", g.config.ListenHTTP, g.config.ListenHTTPS), Info)

	for domain, host := range g.config.VirtualHosts {
		if !host.AutoSSL {
			continue
		}
		certPath, keyPath, err := g.sslManager.obtainCertificate(domain)
		if err != nil {
			g.logger.Log(fmt.Sprintf("Ошибка при получении SSL-сертификата для %s: %v", domain, err), Error)
		} else {
			g.logger.Log(fmt.Sprintf("SSL-сертификат успешно получен для %s.", domain), Info)
		}
		host.SSLCertificate = certPath
		host.SSLKey = keyPath
	}

	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%d", g.config.ListenHTTP), nil)
		if err != nil {
			g.logger.Log(fmt.Sprintf("Ошибка запуска HTTP сервера: %v", err), Error)
		}
	}()

	var firstDomain string
	for _, host := range g.config.VirtualHosts {
		if host.Domain != "" {
			firstDomain = host.Domain
			break
		}
	}
	if firstDomain == "" {
		g.logger.Log("Нет настроенных доменов для HTTPS. HTTPS-сервер не запущен.", Warning)
		return
	}

	certPath := filepath.Join("/etc/gubinnet/ssl", fmt.Sprintf("%s.pem", firstDomain))
	keyPath := filepath.Join("/etc/gubinnet/ssl", fmt.Sprintf("%s-key.pem", firstDomain))
	tlsConfig, err := getTLSConfig(certPath, keyPath)
	if err != nil {
		g.logger.Log(fmt.Sprintf("Ошибка настройки TLS: %v", err), Error)
	} else {
		server := &http.Server{
			Addr:      fmt.Sprintf(":%d", g.config.ListenHTTPS),
			TLSConfig: tlsConfig,
		}
		go func() {
			err := server.ListenAndServeTLS("", "")
			if err != nil {
				g.logger.Log(fmt.Sprintf("Ошибка запуска HTTPS сервера: %v", err), Error)
			}
		}()
	}

	// Запуск health checks
	go g.childProcessMgr.RunHealthChecks(30 * time.Second)
}

// Function to configure modern TLS settings
func getTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
	}
	return tlsConfig, nil
}

// handleRequest handles incoming HTTP requests
func (g *GubinNET) handleRequest(w http.ResponseWriter, r *http.Request) {
	hostHeader := strings.Split(r.Host, ":")[0]
	host, exists := g.config.VirtualHosts[hostHeader]
	if !exists {
		http.Error(w, "Host not found.", http.StatusNotFound)
		return
	}
	if host.InternalPort > 0 {
		internalUrl := fmt.Sprintf("http://127.0.0.1:%d%s", host.InternalPort, r.URL.Path)
		g.proxyRequest(w, r, internalUrl)
		return
	}
	if host.DefaultProxy != "" {
		g.proxyRequest(w, r, host.DefaultProxy)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		challengeToken := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		challengeFilePath := filepath.Join(host.BasePath, ".well-known", "acme-challenge", challengeToken)
		if _, err := os.Stat(challengeFilePath); err == nil {
			content, err := os.ReadFile(challengeFilePath)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			w.Write(content)
			return
		}
		http.Error(w, "Challenge not found.", http.StatusNotFound)
		return
	}
	if r.TLS == nil && host.SSLCertificate != "" {
		redirectURL := fmt.Sprintf("https://%s%s", hostHeader, r.URL.Path)
		http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
		return
	}
	g.serveFileOrSpa(w, r, host)
}

// proxyRequest proxies the request to another server
func (g *GubinNET) proxyRequest(w http.ResponseWriter, r *http.Request, proxyUrl string) {
	client := &http.Client{}
	req, err := http.NewRequest(r.Method, proxyUrl+r.URL.RequestURI(), r.Body)
	if err != nil {
		http.Error(w, "Proxy error", http.StatusBadGateway)
		return
	}
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Proxy error", http.StatusBadGateway)
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

// serveFileOrSpa serves static files or falls back to SPA
func (g *GubinNET) serveFileOrSpa(w http.ResponseWriter, r *http.Request, host *VirtualHost) {
	webRootPath := host.WebRootPath
	if webRootPath == "" {
		webRootPath = host.BasePath
	}
	fullPath := filepath.Join(webRootPath, strings.TrimLeft(r.URL.Path, "/"))
	if fileInfo, err := os.Stat(fullPath); err == nil && !fileInfo.IsDir() {
		g.serveFile(w, fullPath)
		return
	}
	spaFallbackPath := filepath.Join(webRootPath, "index.html")
	if _, err := os.Stat(spaFallbackPath); err == nil {
		g.serveFile(w, spaFallbackPath)
		return
	}
	http.Error(w, "File Not Found", http.StatusNotFound)
}

// serveFile serves a file with appropriate content type
func (g *GubinNET) serveFile(w http.ResponseWriter, filePath string) {
	g.cacheMutex.Lock()
	cached, exists := g.cache[filePath]
	g.cacheMutex.Unlock()
	if exists {
		w.Header().Set("Content-Type", getContentType(filePath))
		w.Write(cached)
		return
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	g.cacheMutex.Lock()
	g.cache[filePath] = content
	g.cacheMutex.Unlock()
	w.Header().Set("Content-Type", getContentType(filePath))
	w.Write(content)
}

// getContentType determines the MIME type based on file extension
func getContentType(filePath string) string {
	ext := filepath.Ext(filePath)
	switch ext {
	case ".html":
		return "text/html"
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".json":
		return "application/json"
	default:
		return "application/octet-stream"
	}
}

// Main entry point
func main() {
	logger := NewLogger("/etc/gubinnet/logs")
	logger.Log("Запуск программы...", Info)

	config := &ConfigParser{}
	err := config.Load("/etc/gubinnet/config.ini")
	if err != nil {
		logger.Log(fmt.Sprintf("Ошибка при загрузке конфигурации: %v", err), Error)
		return
	}

	server := &GubinNET{config: config, logger: logger}
	server.Start()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.Log(fmt.Sprintf("Получен сигнал завершения: %v. Начинаем корректное завершение работы...", sig), Info)

		server.childProcessMgr.mutex.Lock()
		for dllPath, cmd := range server.childProcessMgr.processes {
			logger.Log(fmt.Sprintf("Остановка процесса: %s", dllPath), Info)
			cmd.Process.Kill()
		}
		server.childProcessMgr.mutex.Unlock()

		time.Sleep(5 * time.Second) // Ждем завершения процессов
		logger.Log("Все процессы успешно остановлены.", Info)
		os.Exit(0)
	}()

	// Блокируем основной поток
	select {}
}
