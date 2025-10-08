package security

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// AntiDDoSConfig конфигурация анти-DDoS
type AntiDDoSConfig struct {
	MaxRequestsPerSecond int           `yaml:"max_requests_per_second"`
	BlockDuration        time.Duration `yaml:"block_duration"`
	LogFilePath          string        `yaml:"log_file_path"`
	Whitelist            []string      `yaml:"whitelist"`
	Enabled              bool          `yaml:"enabled"`
}

// IPInfo информация об IP адресе
type IPInfo struct {
	Count        int
	LastSeen     time.Time
	BlockedUntil time.Time
}

// AntiDDoS система защиты от DDoS атак
type AntiDDoS struct {
	cfg           *AntiDDoSConfig
	ipInfo        map[string]*IPInfo
	bannedIPs     map[string]time.Time
	mu            sync.RWMutex
	logFile       *os.File
	whitelist     map[string]bool
	cleanupTicker *time.Ticker
}

// NewAntiDDoS создает новую систему анти-DDoS
func NewAntiDDoS(cfg *AntiDDoSConfig) (*AntiDDoS, error) {
	if cfg.LogFilePath == "" {
		cfg.LogFilePath = "/tmp/antiddos.log"
	}

	logFile, err := os.OpenFile(cfg.LogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	// Создаем whitelist
	whitelist := make(map[string]bool)
	for _, ip := range cfg.Whitelist {
		whitelist[ip] = true
	}

	antiDDoS := &AntiDDoS{
		cfg:       cfg,
		ipInfo:    make(map[string]*IPInfo),
		bannedIPs: make(map[string]time.Time),
		logFile:   logFile,
		whitelist: whitelist,
	}

	// Запускаем очистку устаревших записей
	antiDDoS.startCleanupWorker()

	return antiDDoS, nil
}

// Middleware создает middleware для анти-DDoS защиты
func (a *AntiDDoS) Middleware(next http.Handler) http.Handler {
	if !a.cfg.Enabled {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := a.getRealIP(r)

		// Проверяем whitelist
		if a.whitelist[ip] {
			next.ServeHTTP(w, r)
			return
		}

		// Проверяем блокировку
		if a.isBlocked(ip) {
			a.logToFile(fmt.Sprintf("Blocked request from banned IP: %s", ip))
			http.Error(w, "403 Forbidden - IP temporarily blocked", http.StatusForbidden)
			return
		}

		// Проверяем лимит запросов
		if a.exceedsLimit(ip) {
			a.blockIP(ip)
			a.logToFile(fmt.Sprintf("Blocked IP due to rate limit: %s", ip))
			http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
			return
		}

		// Обновляем счетчик
		a.updateIPCount(ip)

		next.ServeHTTP(w, r)
	})
}

// getRealIP получает реальный IP адрес клиента
func (a *AntiDDoS) getRealIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

// isBlocked проверяет заблокирован ли IP
func (a *AntiDDoS) isBlocked(ip string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	blockTime, exists := a.bannedIPs[ip]
	if !exists {
		return false
	}

	if time.Now().After(blockTime) {
		// Время блокировки истекло
		delete(a.bannedIPs, ip)
		return false
	}

	return true
}

// exceedsLimit проверяет превышает ли IP лимит запросов
func (a *AntiDDoS) exceedsLimit(ip string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	info, exists := a.ipInfo[ip]
	if !exists {
		return false
	}

	// Сбрасываем счетчик если прошла больше секунды
	if time.Since(info.LastSeen) > time.Second {
		return false
	}

	return info.Count > a.cfg.MaxRequestsPerSecond
}

// updateIPCount обновляет счетчик запросов для IP
func (a *AntiDDoS) updateIPCount(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	info, exists := a.ipInfo[ip]

	if !exists {
		a.ipInfo[ip] = &IPInfo{
			Count:    1,
			LastSeen: now,
		}
		return
	}

	// Сбрасываем счетчик если прошла больше секунды
	if now.Sub(info.LastSeen) > time.Second {
		info.Count = 1
		info.LastSeen = now
	} else {
		info.Count++
		info.LastSeen = now
	}
}

// blockIP блокирует IP адрес
func (a *AntiDDoS) blockIP(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.bannedIPs[ip] = time.Now().Add(a.cfg.BlockDuration)

	// Удаляем из счетчиков
	delete(a.ipInfo, ip)
}

// startCleanupWorker запускает воркер для очистки устаревших данных
func (a *AntiDDoS) startCleanupWorker() {
	a.cleanupTicker = time.NewTicker(time.Minute)

	go func() {
		for range a.cleanupTicker.C {
			a.cleanup()
		}
	}()
}

// cleanup очищает устаревшие данные
func (a *AntiDDoS) cleanup() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()

	// Очищаем устаревшие счетчики (старше 2 секунд)
	for ip, info := range a.ipInfo {
		if now.Sub(info.LastSeen) > 2*time.Second {
			delete(a.ipInfo, ip)
		}
	}

	// Очищаем истекшие блокировки
	for ip, blockTime := range a.bannedIPs {
		if now.After(blockTime) {
			delete(a.bannedIPs, ip)
		}
	}
}

// logToFile логирует в файл
func (a *AntiDDoS) logToFile(msg string) {
	timestamp := time.Now().Format(time.RFC3339)
	logMsg := fmt.Sprintf("%s [ANTIDDOS] %s\n", timestamp, msg)
	a.logFile.WriteString(logMsg)
}

// GetStats возвращает статистику
func (a *AntiDDoS) GetStats() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return map[string]interface{}{
		"tracked_ips":   len(a.ipInfo),
		"banned_ips":    len(a.bannedIPs),
		"whitelist_ips": len(a.whitelist),
	}
}

// AddToWhitelist добавляет IP в whitelist
func (a *AntiDDoS) AddToWhitelist(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.whitelist[ip] = true
}

// RemoveFromWhitelist удаляет IP из whitelist
func (a *AntiDDoS) RemoveFromWhitelist(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.whitelist, ip)
}

// Close закрывает анти-DDoS систему
func (a *AntiDDoS) Close() {
	if a.cleanupTicker != nil {
		a.cleanupTicker.Stop()
	}
	if a.logFile != nil {
		a.logFile.Close()
	}
}
