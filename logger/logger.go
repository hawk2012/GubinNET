package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Определение уровня логирования
type LogLevel int

const (
	InfoLevel LogLevel = iota
	WarningLevel
	ErrorLevel
	DebugLevel
)

// Структура логгера
type Logger struct {
	logFilePath string
	mu          sync.Mutex
}

// Создание нового экземпляра логгера
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

// Общий метод для записи логов
func (l *Logger) Log(level LogLevel, message string, fields map[string]interface{}) {
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
	fmt.Println(string(jsonData)) // Вывод в консоль для удобства отладки
	file, err := os.OpenFile(l.logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error writing to log:", err)
		return
	}
	defer file.Close()
	file.WriteString(string(jsonData) + "\n")
}

// Удобные методы для каждого уровня логирования
func (l *Logger) Info(message string, fields map[string]interface{}) {
	l.Log(InfoLevel, message, fields)
}

func (l *Logger) Warning(message string, fields map[string]interface{}) {
	l.Log(WarningLevel, message, fields)
}

func (l *Logger) Warn(message string, fields map[string]interface{}) {
	l.Warning(message, fields)
}

func (l *Logger) Error(message string, fields map[string]interface{}) {
	l.Log(ErrorLevel, message, fields)
}

func (l *Logger) Debug(message string, fields map[string]interface{}) {
	l.Log(DebugLevel, message, fields)
}

// Преобразование уровня логирования в строку
func levelToString(level LogLevel) string {
	switch level {
	case InfoLevel:
		return "INFO"
	case WarningLevel:
		return "WARNING"
	case ErrorLevel:
		return "ERROR"
	case DebugLevel:
		return "DEBUG"
	default:
		return "UNKNOWN"
	}
}
