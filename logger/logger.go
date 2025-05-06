package logger

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type LogLevel int

const (
	DebugLevel LogLevel = iota
	InfoLevel
	WarningLevel
	ErrorLevel
	CriticalLevel
)

type Logger struct {
	logDir       string
	jsonbEnabled bool
	mu           sync.Mutex
	file         *os.File
	compressor   *gzip.Writer
	buffer       *bytes.Buffer
}

func NewLogger(logDir string, jsonbEnabled bool) *Logger {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Println("Failed to create log directory:", err)
		return nil
	}

	currentDate := time.Now().Format("2006-01-02")
	logFile := filepath.Join(logDir, fmt.Sprintf("gubinnet-%s.log", currentDate))

	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Failed to open log file:", err)
		return nil
	}

	buffer := bytes.NewBuffer(nil)
	compressor := gzip.NewWriter(buffer)

	return &Logger{
		logDir:       logDir,
		jsonbEnabled: jsonbEnabled,
		file:         file,
		compressor:   compressor,
		buffer:       buffer,
	}
}

func (l *Logger) Log(level LogLevel, message string, fields map[string]interface{}) {
	logEntry := map[string]interface{}{
		"timestamp": time.Now().UnixNano(),
		"level":     level,
		"message":   message,
	}

	for k, v := range fields {
		logEntry[k] = v
	}

	if l.jsonbEnabled {
		l.writeBinaryLog(logEntry)
	} else {
		l.writeTextLog(logEntry)
	}
}

func (l *Logger) writeBinaryLog(entry map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	jsonData, _ := json.Marshal(entry)
	l.compressor.Write(jsonData)
	l.compressor.Write([]byte{'\n'})
	l.compressor.Flush()

	if l.buffer.Len() > 1024*1024 { // 1MB
		l.file.Write(l.buffer.Bytes())
		l.buffer.Reset()
	}
}

func (l *Logger) writeTextLog(entry map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	formatted := fmt.Sprintf("%v [%d] %s",
		time.Unix(0, entry["timestamp"].(int64)).Format(time.RFC3339Nano),
		entry["level"].(int),
		entry["message"].(string),
	)

	for k, v := range entry {
		if k != "timestamp" && k != "level" && k != "message" {
			formatted += fmt.Sprintf(" %s=%v", k, v)
		}
	}

	fmt.Fprintln(l.file, formatted)
}

func (l *Logger) rotateLogs() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		l.file.Close()
	}

	currentDate := time.Now().Format("2006-01-02")
	logFile := filepath.Join(l.logDir, fmt.Sprintf("gubinnet-%s.log", currentDate))

	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		l.file = file
	}
}

func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.compressor != nil {
		l.compressor.Close()
	}

	if l.file != nil {
		if l.buffer.Len() > 0 {
			l.file.Write(l.buffer.Bytes())
		}
		l.file.Close()
	}
}

func (l *Logger) Debug(message string, fields map[string]interface{}) {
	l.Log(DebugLevel, message, fields)
}

func (l *Logger) Info(message string, fields map[string]interface{}) {
	l.Log(InfoLevel, message, fields)
}

func (l *Logger) Warning(message string, fields map[string]interface{}) {
	l.Log(WarningLevel, message, fields)
}

func (l *Logger) Error(message string, fields map[string]interface{}) {
	l.Log(ErrorLevel, message, fields)
}

func (l *Logger) Critical(message string, fields map[string]interface{}) {
	l.Log(CriticalLevel, message, fields)
}
