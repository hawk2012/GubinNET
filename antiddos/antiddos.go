package antiddos

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"GubinNET/logger" // Импортируем новый пакет логгера
)

// Конфигурация AntiDDoS
type AntiDDoSConfig struct {
	MaxRequestsPerSecond int           // Максимальное количество запросов в секунду с одного IP
	BlockDuration        time.Duration // Длительность блокировки в секундах
}

// Замените все *Logger на *logger.Logger
type AntiDDoS struct {
	config    *AntiDDoSConfig
	ipTracker map[string][]time.Time
	blockList map[string]time.Time
	mu        sync.Mutex
	logger    *logger.Logger // Используем новый логгер
}

func NewAntiDDoS(config *AntiDDoSConfig, logger *logger.Logger) *AntiDDoS {
	return &AntiDDoS{
		config:    config,
		ipTracker: make(map[string][]time.Time),
		blockList: make(map[string]time.Time),
		logger:    logger,
	}
}

// Middleware для защиты от DDoS
func (a *AntiDDoS) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getRealIP(r)
		// Проверяем, заблокирован ли IP
		if a.isBlocked(clientIP) {
			a.logger.Warning("Blocked request from IP", map[string]interface{}{
				"ip": clientIP,
			})
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		// Отслеживаем активность IP
		a.trackRequest(clientIP)
		// Передаем управление дальше
		next(w, r)
	}
}

// Проверка, заблокирован ли IP
func (a *AntiDDoS) isBlocked(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if blockTime, exists := a.blockList[ip]; exists {
		if time.Since(blockTime) < a.config.BlockDuration {
			return true
		}
		delete(a.blockList, ip) // Удаляем из блок-листа по истечении времени
	}
	return false
}

// Отслеживание запросов с IP
func (a *AntiDDoS) trackRequest(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	a.ipTracker[ip] = append(a.ipTracker[ip], now)
	// Очищаем старые записи
	cutoff := now.Add(-1 * time.Second)
	filtered := a.ipTracker[ip][:0]
	for _, t := range a.ipTracker[ip] {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	a.ipTracker[ip] = filtered
	// Если превышено количество запросов, добавляем IP в блок-лист
	if len(a.ipTracker[ip]) > a.config.MaxRequestsPerSecond {
		a.blockList[ip] = now
		a.logger.Log(logger.WarningLevel, "Blocked IP due to excessive requests", map[string]interface{}{
			"ip":     ip,
			"reason": "excessive requests",
		})
	}
}

// Получение реального IP
func getRealIP(r *http.Request) string {
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip = strings.Split(r.RemoteAddr, ":")[0]
	}
	return ip
}

// Добавление IP в чёрный список
func AddToBlacklist(ip string) {
	// Создаем экземпляр AntiDDoS (если он ещё не создан)
	defaultConfig := &AntiDDoSConfig{
		MaxRequestsPerSecond: 100,              // Примерное значение
		BlockDuration:        60 * time.Second, // 1 минута блокировки
	}
	defaultLogger := logger.NewLogger("/etc/gubinnet/logs") // Путь к логам
	antiDDoS := NewAntiDDoS(defaultConfig, defaultLogger)

	antiDDoS.mu.Lock()
	defer antiDDoS.mu.Unlock()

	antiDDoS.blockList[ip] = time.Now()
	antiDDoS.logger.Log(logger.WarningLevel, "Manually added IP to blacklist", map[string]interface{}{
		"ip":     ip,
		"reason": "manual block",
	})
}
