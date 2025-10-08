package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gubinnet/internal/logging"
)

// Manager управляет всеми модулями
type Manager struct {
	modulesDir string
	logger     *logging.Logger
	modules    map[string]Module
	mu         sync.RWMutex
	configs    map[string]*ModuleConfig
}

func NewManager(modulesDir string, logger *logging.Logger) *Manager {
	mgr := &Manager{
		modulesDir: modulesDir,
		logger:     logger,
		modules:    make(map[string]Module),
		configs:    make(map[string]*ModuleConfig),
	}

	// Загружаем конфигурации модулей
	mgr.loadModuleConfigs()

	return mgr
}

// StartAll запускает все модули
func (m *Manager) StartAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entries, err := os.ReadDir(m.modulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			m.logger.Warning("Modules directory not found", map[string]interface{}{
				"path": m.modulesDir,
			})
			return nil
		}
		return fmt.Errorf("read modules directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			moduleName := entry.Name()
			if err := m.startModule(moduleName); err != nil {
				m.logger.Error("Failed to start module", map[string]interface{}{
					"module": moduleName,
					"error":  err,
				})
				// Продолжаем запуск других модулей
				continue
			}
		}
	}

	return nil
}

// StopAll останавливает все модули
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, module := range m.modules {
		if err := module.Stop(); err != nil {
			m.logger.Error("Failed to stop module", map[string]interface{}{
				"module": name,
				"error":  err,
			})
		}
		delete(m.modules, name)
	}
}

// Process выполняет обработку через модуль
func (m *Manager) Process(moduleName, input string) (string, error) {
	m.mu.RLock()
	module, exists := m.modules[moduleName]
	m.mu.RUnlock()

	if !exists {
		// Пытаемся запустить модуль на лету
		if err := m.startModule(moduleName); err != nil {
			return "", fmt.Errorf("module not found: %s", moduleName)
		}

		m.mu.RLock()
		module = m.modules[moduleName]
		m.mu.RUnlock()
	}

	return module.Process(input)
}

// GetModuleInfo возвращает информацию о модуле
func (m *Manager) GetModuleInfo(moduleName string) (*ModuleInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	module, exists := m.modules[moduleName]
	if !exists {
		return nil, fmt.Errorf("module not found: %s", moduleName)
	}

	return &ModuleInfo{
		Name:    module.Name(),
		Type:    "cgo", // Пока только CGO модули
		Enabled: true,
		Running: module.IsRunning(),
	}, nil
}

// ListModules возвращает список всех модулей
func (m *Manager) ListModules() []ModuleInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var infos []ModuleInfo
	for name, module := range m.modules {
		infos = append(infos, ModuleInfo{
			Name:    name,
			Type:    "cgo",
			Enabled: true,
			Running: module.IsRunning(),
		})
	}

	return infos
}

// startModule запускает отдельный модуль
func (m *Manager) startModule(moduleName string) error {
	moduleDir := filepath.Join(m.modulesDir, moduleName)
	moduleSo := filepath.Join(moduleDir, "module.so")
	sourceCpp := filepath.Join(moduleDir, "module.cpp")

	// Проверяем существование модуля
	if _, err := os.Stat(moduleDir); os.IsNotExist(err) {
		return fmt.Errorf("module directory not found: %s", moduleDir)
	}

	// Компилируем если нужно
	if _, err := os.Stat(moduleSo); os.IsNotExist(err) {
		if _, err := os.Stat(sourceCpp); err == nil {
			m.logger.Info("Compiling module", map[string]interface{}{
				"module": moduleName,
			})

			if err := compileCppModule(moduleDir, sourceCpp); err != nil {
				return fmt.Errorf("compile module: %w", err)
			}
		} else {
			return fmt.Errorf("module binary not found and no source code")
		}
	}

	// Создаем и запускаем модуль
	config := m.getModuleConfig(moduleName)
	module := NewCGOModule(moduleName, moduleSo, m.logger, config.Interval)

	if err := module.Start(); err != nil {
		return fmt.Errorf("start module: %w", err)
	}

	m.modules[moduleName] = module
	m.logger.Info("Module started", map[string]interface{}{
		"module": moduleName,
	})

	return nil
}

// loadModuleConfigs загружает конфигурации модулей
func (m *Manager) loadModuleConfigs() {
	// Пока используем дефолтные настройки
	// В будущем можно загружать из YAML/JSON файлов
}

// getModuleConfig возвращает конфигурацию модуля
func (m *Manager) getModuleConfig(moduleName string) *ModuleConfig {
	if config, exists := m.configs[moduleName]; exists {
		return config
	}

	// Дефолтная конфигурация
	return &ModuleConfig{
		Enabled:  true,
		Path:     filepath.Join(m.modulesDir, moduleName, "module.so"),
		Interval: 10 * time.Second,
		Timeout:  30 * time.Second,
	}
}
