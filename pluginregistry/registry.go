// pluginregistry/registry.go

package pluginregistry

import (
	"net/http"
	"sync"
)

// Интерфейс плагина (дублируется здесь для ясности)
type Plugin interface {
	Name() string
	Execute(w http.ResponseWriter, r *http.Request) bool
}

// Реестр плагинов
var (
	pluginsRegistry []Plugin
	registryMutex   sync.Mutex
)

// RegisterPlugin регистрирует новый плагин
func RegisterPlugin(p Plugin) {
	registryMutex.Lock()
	defer registryMutex.Unlock()

	// Проверяем, что плагин еще не зарегистрирован
	for _, registered := range pluginsRegistry {
		if registered.Name() == p.Name() {
			return // Плагин уже зарегистрирован
		}
	}

	// Добавляем плагин в реестр
	pluginsRegistry = append(pluginsRegistry, p)
}

// GetPlugins возвращает список всех зарегистрированных плагинов
func GetPlugins() []Plugin {
	registryMutex.Lock()
	defer registryMutex.Unlock()

	// Создаем копию списка плагинов для предотвращения внешних изменений
	result := make([]Plugin, len(pluginsRegistry))
	copy(result, pluginsRegistry)
	return result
}

// ExecutePlugins выполняет все зарегистрированные плагины по очереди
func ExecutePlugins(w http.ResponseWriter, r *http.Request) bool {
	registryMutex.Lock()
	defer registryMutex.Unlock()

	for _, plugin := range pluginsRegistry {
		if plugin.Execute(w, r) {
			return true // Если плагин обработал запрос, завершаем выполнение
		}
	}
	return false // Никакой плагин не обработал запрос
}
