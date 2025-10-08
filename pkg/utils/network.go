package utils

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// GetRealIP возвращает реальный IP адрес клиента
func GetRealIP(r *http.Request) string {
	// Пробуем разные заголовки
	headers := []string{"X-Real-IP", "X-Forwarded-For", "CF-Connecting-IP"}

	for _, header := range headers {
		if ip := r.Header.Get(header); ip != "" {
			// Для X-Forwarded-For берем первый IP
			if header == "X-Forwarded-For" {
				if parts := strings.Split(ip, ","); len(parts) > 0 {
					ip = strings.TrimSpace(parts[0])
				}
			}

			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// Если заголовков нет, используем RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Если SplitHostPort вернул ошибку, возможно это просто IP
		if net.ParseIP(r.RemoteAddr) != nil {
			return r.RemoteAddr
		}
		return "unknown"
	}

	return ip
}

// IsPrivateIP проверяет является ли IP приватным
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// ValidateIP проверяет валидность IP адреса
func ValidateIP(ipStr string) bool {
	return net.ParseIP(ipStr) != nil
}

// GetHostname возвращает hostname из запроса
func GetHostname(r *http.Request) string {
	host := r.Host
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}
	return host
}

// IsLocalhost проверяет является ли хост localhost
func IsLocalhost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// PortAvailable проверяет доступен ли порт
func PortAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// FindAvailablePort находит доступный порт
func FindAvailablePort(startPort int) (int, error) {
	for port := startPort; port < startPort+100; port++ {
		if PortAvailable(port) {
			return port, nil
		}
	}
	return 0, fmt.Errorf("no available port found in range %d-%d", startPort, startPort+100)
}

// URLJoin объединяет части URL
func URLJoin(base string, paths ...string) string {
	url := strings.TrimSuffix(base, "/")
	for _, path := range paths {
		url += "/" + strings.TrimPrefix(path, "/")
	}
	return url
}

// SanitizeFilename очищает имя файла от опасных символов
func SanitizeFilename(filename string) string {
	// Удаляем опасные символы
	dangerous := []string{"..", "/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	for _, char := range dangerous {
		filename = strings.ReplaceAll(filename, char, "_")
	}
	return filename
}
