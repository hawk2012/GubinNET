package logging

import (
	"fmt"
	"log"
	"os"
)

// ModuleLogger логгер для модулей
type ModuleLogger struct {
	logger *log.Logger
}

// NewModuleLogger создает новый логгер для модулей
func NewModuleLogger() *ModuleLogger {
	return &ModuleLogger{
		logger: log.New(os.Stdout, "[MODULE] ", log.LstdFlags|log.Lmsgprefix),
	}
}

// Log логирует сообщение модуля
func (ml *ModuleLogger) Log(moduleName, message string) {
	ml.logger.Printf("[%s] %s", moduleName, message)
}

// Logf логирует форматированное сообщение модуля
func (ml *ModuleLogger) Logf(moduleName, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	ml.Log(moduleName, message)
}

// Error логирует ошибку модуля
func (ml *ModuleLogger) Error(moduleName, message string) {
	ml.logger.Printf("[%s] ERROR: %s", moduleName, message)
}

// Errorf логирует форматированную ошибку модуля
func (ml *ModuleLogger) Errorf(moduleName, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	ml.Error(moduleName, message)
}

// WithModule создает логгер для конкретного модуля
func (ml *ModuleLogger) WithModule(moduleName string) *ModuleSpecificLogger {
	return &ModuleSpecificLogger{
		moduleLogger: ml,
		moduleName:   moduleName,
	}
}

// ModuleSpecificLogger логгер для конкретного модуля
type ModuleSpecificLogger struct {
	moduleLogger *ModuleLogger
	moduleName   string
}

func (m *ModuleSpecificLogger) Log(message string) {
	m.moduleLogger.Log(m.moduleName, message)
}

func (m *ModuleSpecificLogger) Logf(format string, args ...interface{}) {
	m.moduleLogger.Logf(m.moduleName, format, args...)
}

func (m *ModuleSpecificLogger) Error(message string) {
	m.moduleLogger.Error(m.moduleName, message)
}

func (m *ModuleSpecificLogger) Errorf(format string, args ...interface{}) {
	m.moduleLogger.Errorf(m.moduleName, format, args...)
}
