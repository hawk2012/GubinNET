package modules

import "time"

// Module интерфейс для всех типов модулей
type Module interface {
	Start() error
	Stop() error
	Process(input string) (string, error)
	Name() string
	IsRunning() bool
	HealthCheck() error
}

// ModuleConfig конфигурация модуля
type ModuleConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Path     string        `yaml:"path"`
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
}

// ModuleInfo информация о модуле
type ModuleInfo struct {
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Enabled   bool      `json:"enabled"`
	Running   bool      `json:"running"`
	LastError string    `json:"last_error,omitempty"`
	StartedAt time.Time `json:"started_at,omitempty"`
}
