// plugins/register.go

package plugins

import (
	"net/http"
	"strings"

	"GubinNET/pluginregistry"
)

// Name возвращает имя плагина
func (p *WSSPlugin) Name() string {
	return "WebSocketSupportPlugin"
}

// Execute выполняет логику плагина
func (p *WSSPlugin) Execute(w http.ResponseWriter, r *http.Request) bool {
	// Пример: Проверяем, является ли запрос WebSocket-соединением
	if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
		// Обработка WebSocket-запроса
		w.Write([]byte("WebSocket connection established"))
		return true // Запрос обработан плагином
	}
	return false // Запрос не обработан плагином
}

// RegisterWSSPlugin регистрирует плагин в реестре плагинов
func RegisterWSSPlugin() {
	pluginregistry.RegisterPlugin(plugin)
}
