package core

import (
	"net/http"
)

// Интерфейс для плагинов
type Plugin interface {
	Name() string
	Execute(w http.ResponseWriter, r *http.Request) bool
}

var registeredPlugins []Plugin

// Функция для регистрации плагинов
func RegisterPlugin(p Plugin) {
	registeredPlugins = append(registeredPlugins, p)
}
