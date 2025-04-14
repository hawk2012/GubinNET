package main

import (
	"crypto/tls"
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
	absLogDir, err := filepath.Abs(logDirectory)
	if err != nil {
		fmt.Println("Неверный путь к логам:", err)
		return nil
	}
	if _, err := os.Stat(absLogDir); os.IsNotExist(err) {
		os.MkdirAll(absLogDir, 0755)
	}
	logFileName := fmt.Sprintf("log_%s.txt", time.Now().Format("20060102"))
	logFilePath := filepath.Join(absLogDir, logFileName)
	return &Logger{logFilePath: logFilePath}
}

// Log writes a message to the log file and console
func (l *Logger) Log(message string, level LogLevel) {
	levelStr := levelToString(level)
	logEntry := fmt.Sprintf("[%s] [%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), levelStr, message)
	fmt.Print(logEntry)
	file, err := os.OpenFile(l.logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Ошибка записи в лог:", err)
		return
	}
	defer file.Close()
	file.WriteString(logEntry)
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

// ConfigParser handles configuration parsing
type ConfigParser struct {
	ListenHTTP   int
	ListenHTTPS  int
	ConfigPath   string
	VirtualHosts map[string]*VirtualHost
	PHPConfig    *PHPSettings
	logger       *Logger
}

// VirtualHost represents a virtual host configuration
type VirtualHost struct {
	Domain         string
	BasePath       string
	WebRootPath    string
	DefaultProxy   string
	InternalPort   int
	SSLCertificate string
	SSLKey         string
}

// PHPSettings represents PHP configuration
type PHPSettings struct {
	Enabled     bool
	BinaryPath  string
	WebRootPath string
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
				c.logger.Log(fmt.Sprintf("Загружен хост: %s", hostName), Info)
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
				if err != nil {
					c.logger.Log(fmt.Sprintf("Неверное значение InternalPort: %s", value), Error)
					continue
				}
				currentHost.InternalPort = port
			case "SSLCertificate":
				currentHost.SSLCertificate = value
			case "SSLKey":
				currentHost.SSLKey = value
			}
		} else if c.PHPConfig != nil {
			switch key {
			case "Enabled":
				c.PHPConfig.Enabled, _ = strconv.ParseBool(value)
			case "BinaryPath":
				absBinPath, err := filepath.Abs(value)
				if err != nil {
					c.logger.Log(fmt.Sprintf("Неверный путь для PHP BinaryPath: %s", value), Error)
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
					c.logger.Log(fmt.Sprintf("Неверный путь для ConfigPath: %s", value), Error)
					continue
				}
				c.ConfigPath = absConfigPath
			}
		}
	}
	return nil
}

// GubinNET represents the main server structure
type GubinNET struct {
	config *ConfigParser
	logger *Logger
	cache  map[string][]byte
	mu     sync.Mutex
}

// Start starts the HTTP and HTTPS servers with SNI support
func (g *GubinNET) Start() {
	g.logger.Log("Запуск сервера...", Info)
	g.cache = make(map[string][]byte)

	// Настройка HTTP-сервера с поддержкой SNI
	httpServer := &http.Server{
		Addr: fmt.Sprintf(":%d", g.config.ListenHTTP),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g.handleRequest(w, r)
		}),
	}
	go func() {
		g.logger.Log(fmt.Sprintf("HTTP сервер запущен на порту %d с поддержкой SNI.", g.config.ListenHTTP), Info)
		err := httpServer.ListenAndServe()
		if err != nil {
			g.logger.Log(fmt.Sprintf("Ошибка запуска HTTP сервера: %v", err), Error)
		}
	}()

	// Настройка HTTPS-сервера с поддержкой SNI
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host, exists := g.config.VirtualHosts[hello.ServerName]
			if !exists || host.SSLCertificate == "" || host.SSLKey == "" {
				return nil, fmt.Errorf("certificate not found for host: %s", hello.ServerName)
			}
			cert, err := tls.LoadX509KeyPair(host.SSLCertificate, host.SSLKey)
			if err != nil {
				g.logger.Log(fmt.Sprintf("Ошибка загрузки сертификата для хоста %s: %v", hello.ServerName, err), Error)
				return nil, err
			}
			return &cert, nil
		},
	}
	httpsServer := &http.Server{
		Addr:      fmt.Sprintf(":%d", g.config.ListenHTTPS),
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g.handleRequest(w, r)
		}),
	}
	go func() {
		g.logger.Log(fmt.Sprintf("HTTPS сервер запущен на порту %d с поддержкой SNI.", g.config.ListenHTTPS), Info)
		err := httpsServer.ListenAndServeTLS("", "")
		if err != nil {
			g.logger.Log(fmt.Sprintf("Ошибка запуска HTTPS сервера: %v", err), Error)
		}
	}()

	// Обработка сигналов завершения
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		g.logger.Log("Получен сигнал завершения. Начинаем корректное завершение работы...", Info)
		time.Sleep(5 * time.Second)
		g.logger.Log("Сервер успешно остановлен.", Info)
		os.Exit(0)
	}()
}

// handleRequest handles incoming HTTP requests
func (g *GubinNET) handleRequest(w http.ResponseWriter, r *http.Request) {
	serverInfo := "GubinNET/1.0;"
	w.Header().Set("Server", serverInfo)
	hostHeader := strings.Split(r.Host, ":")[0]
	host, exists := g.config.VirtualHosts[hostHeader]
	if !exists {
		g.serveErrorPage(w, r, http.StatusNotFound, "Host not found.")
		return
	}

	// Если DefaultProxy задан, проксируем запрос
	if host.DefaultProxy != "" {
		g.proxyRequest(w, r, host.DefaultProxy)
		return
	}

	// Если InternalPort задан и не используется PHP, проксируем запрос на InternalPort
	if host.InternalPort != 0 && !g.config.PHPConfig.Enabled {
		proxyUrl := fmt.Sprintf("http://127.0.0.1:%d", host.InternalPort)
		g.proxyRequest(w, r, proxyUrl)
		return
	}

	// В противном случае обслуживаем файлы или SPA
	g.serveFileOrSpa(w, r, host)
}

// proxyRequest proxies the request to another server
func (g *GubinNET) proxyRequest(w http.ResponseWriter, r *http.Request, proxyUrl string) {
	client := &http.Client{}
	req, err := http.NewRequest(r.Method, proxyUrl+r.URL.RequestURI(), r.Body)
	if err != nil {
		g.serveErrorPage(w, r, http.StatusBadGateway, "Proxy error.")
		return
	}
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		g.serveErrorPage(w, r, http.StatusBadGateway, "Proxy error.")
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
	g.serveErrorPage(w, r, http.StatusNotFound, "File Not Found.")
}

// serveFile serves a file with appropriate content type
func (g *GubinNET) serveFile(w http.ResponseWriter, filePath string) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		g.serveErrorPage(w, nil, http.StatusInternalServerError, "Internal Server Error.")
		return
	}
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

// serveErrorPage generates standard error pages with server signature
func (g *GubinNET) serveErrorPage(w http.ResponseWriter, r *http.Request, statusCode int, message string) {
	w.Header().Set("Server", "GubinNET/1.0")
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
    <p>Server: GubinNET/1.0</p>
</body>
</html>
`, statusCode, statusCode, message)
	w.Write([]byte(html))
}

// Main entry point
func main() {
	logger := NewLogger("/etc/gubinnet/logs")
	logger.Log("Запуск программы...", Info)
	config := &ConfigParser{logger: logger}
	err := config.Load("/etc/gubinnet/config.ini")
	if err != nil {
		logger.Log(fmt.Sprintf("Ошибка при загрузке конфигурации: %v", err), Error)
		return
	}
	server := &GubinNET{config: config, logger: logger}
	server.Start()
	select {}
}
