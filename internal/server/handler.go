package server

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gubinnet/internal/config"
)

func (s *GubinServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	hostHeader := strings.Split(strings.TrimSuffix(r.Host, ";"), ":")[0]
	host, exists := s.config.VirtualHosts[hostHeader]

	if !exists || host.Root == "" {
		requestID := w.Header().Get("X-Request-ID")
		s.serveHostNotFoundPage(w, r, requestID)
		return
	}

	// Редирект на HTTPS если нужно
	if host.RedirectToHTTPS && r.TLS == nil {
		target := "https://" + hostHeader + r.URL.String()
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
		return
	}

	// Обработка модулей
	if strings.HasPrefix(r.URL.Path, "/modules/") {
		s.handleModuleRequest(w, r, hostHeader)
		return
	}

	// Статические файлы или прокси
	requestID := w.Header().Get("X-Request-ID")
	s.serveFileOrProxy(w, r, host, requestID)
}

func (s *GubinServer) handleModuleRequest(w http.ResponseWriter, r *http.Request, host string) {
	moduleName := strings.TrimPrefix(r.URL.Path, "/modules/")

	output, err := s.modules.Process(moduleName, r.URL.Query().Get("input"))
	if err != nil {
		requestID := w.Header().Get("X-Request-ID")
		s.serveErrorPage(w, r, http.StatusInternalServerError,
			"Module Error", err.Error(), requestID)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, output)
}

func (s *GubinServer) serveFileOrProxy(w http.ResponseWriter, r *http.Request, host *config.VirtualHost, requestID string) {
	if host.ProxyURL != "" {
		s.handleProxy(w, r, host.ProxyURL, requestID)
		return
	}

	webRootPath := host.Root
	if webRootPath == "" {
		s.serveErrorPage(w, r, http.StatusInternalServerError,
			"Server configuration error", "", requestID)
		return
	}

	requestPath := filepath.Clean(strings.TrimLeft(r.URL.Path, "/"))
	fullPath := filepath.Join(webRootPath, requestPath)

	fileInfo, err := s.findFile(fullPath, host)
	if err != nil {
		s.serveErrorPage(w, r, http.StatusNotFound,
			"File Not Found",
			fmt.Sprintf("File '%s' does not exist", requestPath),
			requestID)
		return
	}

	s.serveFile(w, r, fullPath, fileInfo, requestID)
}

func (s *GubinServer) findFile(fullPath string, host *config.VirtualHost) (fileInfo interface{}, err error) {
	// Проверяем прямое совпадение
	if info, err := os.Stat(fullPath); err == nil {
		if info.IsDir() {
			// Ищем index файлы в директории
			indexFiles := []string{"index.html", "index.htm", "default.htm"}
			if host.Index != "" {
				indexFiles = append([]string{host.Index}, indexFiles...)
			}

			for _, index := range indexFiles {
				indexPath := filepath.Join(fullPath, index)
				if stat, err := os.Stat(indexPath); err == nil && !stat.IsDir() {
					return stat, nil
				}
			}
			return nil, fmt.Errorf("no index file found")
		}
		return info, nil
	}

	// Пробуем try_files
	if len(host.TryFiles) > 0 {
		for _, tryFile := range host.TryFiles {
			tryPath := strings.Replace(tryFile, "$uri", strings.TrimLeft(r.URL.Path, "/"), 1)
			tryPath = filepath.Join(host.Root, tryPath)

			if stat, err := os.Stat(tryPath); err == nil && !stat.IsDir() {
				return stat, nil
			}
		}
	}

	return nil, fmt.Errorf("file not found")
}

func (s *GubinServer) handleProxy(w http.ResponseWriter, r *http.Request, proxyURL string, requestID string) {
	targetURL, err := url.Parse(proxyURL + r.URL.String())
	if err != nil {
		s.serveErrorPage(w, r, http.StatusInternalServerError,
			"Proxy configuration error", "", requestID)
		return
	}

	// Создаем прокси-запрос
	proxyReq, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		s.serveErrorPage(w, r, http.StatusInternalServerError,
			"Internal Server Error", "", requestID)
		return
	}

	// Копируем заголовки
	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Выполняем запрос
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(proxyReq)
	if err != nil {
		s.serveErrorPage(w, r, http.StatusBadGateway,
			"Bad Gateway", "", requestID)
		return
	}
	defer resp.Body.Close()

	// Копируем заголовки ответа
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (s *GubinServer) serveFile(w http.ResponseWriter, r *http.Request, filePath string, fileInfo os.FileInfo, requestID string) {
	// Используем кэш
	content, contentType, err := s.cache.Get(filePath, fileInfo)
	if err != nil {
		s.serveErrorPage(w, r, http.StatusInternalServerError,
			"Internal Server Error", "", requestID)
		return
	}

	w.Header().Set("Content-Type", contentType)

	// Поддержка gzip
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		gz.Write(content)
	} else {
		w.Write(content)
	}
}

func (s *GubinServer) serveErrorPage(w http.ResponseWriter, r *http.Request, statusCode int, message string, details string, requestID string) {
	s.logger.Error("Error page served", map[string]interface{}{
		"path":       r.URL.Path,
		"method":     r.Method,
		"status":     statusCode,
		"message":    message,
		"details":    details,
		"remote":     s.getRealIP(r),
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
    <p>Server: GubinNET/2.0.0</p>
    <p>Request ID: %s</p>
</body>
</html>`, statusCode, statusCode, message, details, requestID)

	w.Write([]byte(html))
}

func (s *GubinServer) serveHostNotFoundPage(w http.ResponseWriter, r *http.Request, requestID string) {
	s.logger.Error("Host not found", map[string]interface{}{
		"host":       r.Host,
		"path":       r.URL.Path,
		"method":     r.Method,
		"remote":     s.getRealIP(r),
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
    <p>Server: GubinNET/2.0.0</p>
</body>
</html>`

	w.Write([]byte(html))
}
