package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger структура логгера
type Logger struct {
	file   *os.File
	json   bool
	mu     sync.Mutex
	config *LogConfig
}

// LogConfig конфигурация логгера
type LogConfig struct {
	Dir        string
	JSON       bool
	MaxSize    int64
	MaxBackups int
}

// NewLogger создает новый логгер
func NewLogger(logDir string, json bool) *Logger {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("Failed to create log directory: %v\n", err)
		return nil
	}

	logFile := filepath.Join(logDir, "access.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to open log file: %v\n", err)
		return nil
	}

	return &Logger{
		file: f,
		json: json,
		config: &LogConfig{
			Dir:        logDir,
			JSON:       json,
			MaxSize:    100 * 1024 * 1024, // 100MB
			MaxBackups: 10,
		},
	}
}

// Info логирует информационное сообщение
func (l *Logger) Info(msg string, fields map[string]interface{}) {
	l.log("INFO", msg, fields)
}

// Warning логирует предупреждение
func (l *Logger) Warning(msg string, fields map[string]interface{}) {
	l.log("WARNING", msg, fields)
}

// Error логирует ошибку
func (l *Logger) Error(msg string, fields map[string]interface{}) {
	l.log("ERROR", msg, fields)
}

// log основная функция логирования
func (l *Logger) log(level, msg string, fields map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().Format(time.RFC3339)

	if l.json {
		l.writeJSONLog(timestamp, level, msg, fields)
	} else {
		l.writeTextLog(timestamp, level, msg, fields)
	}
}

// writeJSONLog записывает лог в JSON формате
func (l *Logger) writeJSONLog(timestamp, level, msg string, fields map[string]interface{}) {
	// Базовые поля
	logEntry := map[string]interface{}{
		"timestamp": timestamp,
		"level":     level,
		"message":   msg,
	}

	// Добавляем пользовательские поля
	for k, v := range fields {
		logEntry[k] = v
	}

	// Простая JSON сериализация (можно заменить на encoding/json)
	jsonStr := "{"
	jsonStr += fmt.Sprintf(`"timestamp":"%s",`, timestamp)
	jsonStr += fmt.Sprintf(`"level":"%s",`, level)
	jsonStr += fmt.Sprintf(`"message":"%s"`, msg)

	for k, v := range fields {
		jsonStr += fmt.Sprintf(`,"%s":"%v"`, k, v)
	}
	jsonStr += "}\n"

	l.file.WriteString(jsonStr)
}

// writeTextLog записывает лог в текстовом формате
func (l *Logger) writeTextLog(timestamp, level, msg string, fields map[string]interface{}) {
	fieldsStr := ""
	for k, v := range fields {
		fieldsStr += fmt.Sprintf(" %s=\"%v\"", k, v)
	}

	line := fmt.Sprintf("%s [%s]%s %s\n", timestamp, level, fieldsStr, msg)
	l.file.WriteString(line)
}

// Close закрывает логгер
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		l.file.Close()
		l.file = nil
	}
}

// StartAutoRotate запускает автоматическую ротацию логов
func (l *Logger) StartAutoRotate() {
	go func() {
		ticker := time.NewTicker(24 * time.Hour) // Проверка каждые 24 часа
		defer ticker.Stop()

		for range ticker.C {
			l.rotateIfNeeded()
		}
	}()
}

// rotateIfNeeded выполняет ротацию логов если нужно
func (l *Logger) rotateIfNeeded() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return
	}

	// Проверяем размер файла
	info, err := l.file.Stat()
	if err != nil {
		return
	}

	if info.Size() < l.config.MaxSize {
		return
	}

	// Выполняем ротацию
	l.rotate()
}

// rotate выполняет ротацию логов
func (l *Logger) rotate() {
	if l.file != nil {
		l.file.Close()
	}

	// Создаем backup существующего файла
	oldPath := filepath.Join(l.config.Dir, "access.log")
	backupPath := filepath.Join(l.config.Dir,
		fmt.Sprintf("access.%s.log", time.Now().Format("20060102-150405")))

	if err := os.Rename(oldPath, backupPath); err != nil {
		fmt.Printf("Failed to rotate log file: %v\n", err)
	}

	// Создаем новый файл
	f, err := os.OpenFile(oldPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to create new log file: %v\n", err)
		return
	}

	l.file = f

	// Очищаем старые backup файлы
	l.cleanupOldBackups()
}

// cleanupOldBackups удаляет старые backup файлы
func (l *Logger) cleanupOldBackups() {
	files, err := os.ReadDir(l.config.Dir)
	if err != nil {
		return
	}

	var backupFiles []string
	for _, file := range files {
		if !file.IsDir() && isBackupFile(file.Name()) {
			backupFiles = append(backupFiles, filepath.Join(l.config.Dir, file.Name()))
		}
	}

	// Удаляем самые старые файлы если превышен лимит
	if len(backupFiles) > l.config.MaxBackups {
		// Сортируем по времени модификации
		for i := 0; i < len(backupFiles)-l.config.MaxBackups; i++ {
			os.Remove(backupFiles[i])
		}
	}
}

// isBackupFile проверяет является ли файл backup файлом
func isBackupFile(filename string) bool {
	return len(filename) > 4 && filename[:6] == "access." && filename[len(filename)-4:] == ".log"
}

// WithFields создает новый логгер с дополнительными полями
func (l *Logger) WithFields(fields map[string]interface{}) *LoggerWithFields {
	return &LoggerWithFields{
		logger: l,
		fields: fields,
	}
}

// LoggerWithFields логгер с предустановленными полями
type LoggerWithFields struct {
	logger *Logger
	fields map[string]interface{}
}

func (l *LoggerWithFields) Info(msg string, fields map[string]interface{}) {
	merged := mergeFields(l.fields, fields)
	l.logger.Info(msg, merged)
}

func (l *LoggerWithFields) Warning(msg string, fields map[string]interface{}) {
	merged := mergeFields(l.fields, fields)
	l.logger.Warning(msg, merged)
}

func (l *LoggerWithFields) Error(msg string, fields map[string]interface{}) {
	merged := mergeFields(l.fields, fields)
	l.logger.Error(msg, merged)
}

// mergeFields объединяет поля
func mergeFields(base, additional map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range base {
		result[k] = v
	}
	for k, v := range additional {
		result[k] = v
	}
	return result
}
