package antiddos

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Конфигурация AntiDDoS
type AntiDDoSConfig struct {
	MaxRequestsPerSecond int           // Максимальное количество запросов в секунду с одного IP
	BlockDuration        time.Duration // Длительность блокировки в секундах
	LogFilePath          string        // Путь к файлу логов
}

// Структура AntiDDoS
type AntiDDoS struct {
	config    *AntiDDoSConfig
	ipTracker map[string][]time.Time
	blockList map[string]time.Time
	mu        sync.Mutex
	logFile   *os.File
}

// Создание нового экземпляра AntiDDoS
func NewAntiDDoS(config *AntiDDoSConfig) (*AntiDDoS, error) {
	// Открываем файл логов
	logFile, err := os.OpenFile(config.LogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	return &AntiDDoS{
		config:    config,
		ipTracker: make(map[string][]time.Time),
		blockList: make(map[string]time.Time),
		logFile:   logFile,
	}, nil
}

// Middleware для защиты от DDoS
func (a *AntiDDoS) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getRealIP(r)

		// Проверяем, заблокирован ли IP
		if a.isBlocked(clientIP) {
			a.log(fmt.Sprintf("BLOCKED|%s|Too many requests", clientIP))
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		// Отслеживаем активность IP
		a.trackRequest(clientIP)

		// Передаем управление дальше
		next(w, r)
	}
}

// Закрытие файла логов
func (a *AntiDDoS) Close() error {
	if a.logFile != nil {
		return a.logFile.Close()
	}
	return nil
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
		a.log(fmt.Sprintf("BLOCKED|%s|Excessive requests|Count:%d", ip, len(a.ipTracker[ip])))
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

// Логирование
func (a *AntiDDoS) log(message string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logMessage := fmt.Sprintf("%s|%s\n", timestamp, message)

	// Пишем в файл
	if a.logFile != nil {
		a.logFile.WriteString(logMessage)
	}

	// Также выводим в консоль
	fmt.Print(logMessage)
}

// Добавление IP в чёрный список
func (a *AntiDDoS) AddToBlacklist(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.blockList[ip] = time.Now()
	a.log(fmt.Sprintf("MANUAL_BLOCK|%s|Manual block", ip))
}
