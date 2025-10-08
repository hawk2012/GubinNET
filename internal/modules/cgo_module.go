package modules

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef char* (*process_func)(const char*);

void* load_library(const char* path) {
    return dlopen(path, RTLD_LAZY);
}

process_func get_process_function(void* handle) {
    return (process_func)dlsym(handle, "process");
}

char* call_process(process_func fn, const char* input) {
    if (!fn) return NULL;
    return fn(input);
}

void free_library(void* handle) {
    dlclose(handle);
}
*/
import "C"
import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	"gubinnet/internal/logging"
)

// CGOModule модуль на CGO
type CGOModule struct {
	name     string
	path     string
	handle   unsafe.Pointer
	fn       C.process_func
	running  bool
	logger   *logging.Logger
	interval time.Duration
	mu       sync.RWMutex
}

// NewCGOModule создает новый CGO модуль
func NewCGOModule(name, path string, logger *logging.Logger, interval time.Duration) *CGOModule {
	return &CGOModule{
		name:     name,
		path:     path,
		logger:   logger,
		interval: interval,
	}
}

// Start запускает модуль
func (m *CGOModule) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("module already running")
	}

	// Загружаем библиотеку
	cPath := C.CString(m.path)
	defer C.free(unsafe.Pointer(cPath))

	handle := C.load_library(cPath)
	if handle == nil {
		return fmt.Errorf("failed to load library: %s", m.path)
	}
	m.handle = handle

	// Получаем функцию
	fn := C.get_process_function(handle)
	if fn == nil {
		C.free_library(handle)
		return fmt.Errorf("function 'process' not found in library")
	}
	m.fn = fn

	m.running = true

	// Запускаем фоновую обработку
	go m.backgroundWorker()

	m.logger.Info("CGO module started", map[string]interface{}{
		"module": m.name,
		"path":   m.path,
	})

	return nil
}

// Stop останавливает модуль
func (m *CGOModule) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	m.running = false

	if m.handle != nil {
		C.free_library(m.handle)
		m.handle = nil
		m.fn = nil
	}

	m.logger.Info("CGO module stopped", map[string]interface{}{
		"module": m.name,
	})

	return nil
}

// Process выполняет обработку
func (m *CGOModule) Process(input string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.running {
		return "", fmt.Errorf("module not running")
	}

	if m.fn == nil {
		return "", fmt.Errorf("module function not available")
	}

	cInput := C.CString(input)
	defer C.free(unsafe.Pointer(cInput))

	result := C.call_process(m.fn, cInput)
	if result == nil {
		return "", fmt.Errorf("module returned NULL")
	}
	defer C.free(unsafe.Pointer(result))

	return C.GoString(result), nil
}

// Name возвращает имя модуля
func (m *CGOModule) Name() string {
	return m.name
}

// IsRunning проверяет запущен ли модуль
func (m *CGOModule) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// HealthCheck проверяет здоровье модуля
func (m *CGOModule) HealthCheck() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.running {
		return fmt.Errorf("module not running")
	}

	// Тестовый вызов
	cInput := C.CString("healthcheck")
	defer C.free(unsafe.Pointer(cInput))

	result := C.call_process(m.fn, cInput)
	if result == nil {
		return fmt.Errorf("healthcheck failed")
	}
	C.free(unsafe.Pointer(result))

	return nil
}

// backgroundWorker фоновый воркер модуля
func (m *CGOModule) backgroundWorker() {
	for {
		m.mu.RLock()
		running := m.running
		m.mu.RUnlock()

		if !running {
			break
		}

		// Выполняем фоновую задачу
		if output, err := m.Process("background"); err == nil {
			m.logger.Info("Background task executed", map[string]interface{}{
				"module": m.name,
				"output": output,
			})
		} else {
			m.logger.Error("Background task failed", map[string]interface{}{
				"module": m.name,
				"error":  err,
			})
		}

		time.Sleep(m.interval)
	}
}
