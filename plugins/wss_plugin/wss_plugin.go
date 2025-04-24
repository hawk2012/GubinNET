package plugins

import (
	"net/http"
	"strings"

	"GubinNET/core"
)

// WSSPlugin реализует поддержку WebSocket
type WSSPlugin struct{}

// Name возвращает имя плагина
func (p *WSSPlugin) Name() string {
	return "WebSocketSupportPlugin"
}

// Execute выполняет логику плагина
func (p *WSSPlugin) Execute(w http.ResponseWriter, r *http.Request) bool {
	// Проверяем, является ли запрос WebSocket-соединением
	if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Websocket not supported", http.StatusServiceUnavailable)
			return true
		}

		conn, bufrw, err := hijacker.Hijack()
		if err != nil {
			http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
			return true
		}

		// Отправляем handshake response
		bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
		bufrw.WriteString("Upgrade: websocket\r\n")
		bufrw.WriteString("Connection: Upgrade\r\n")
		bufrw.WriteString("\r\n")
		bufrw.Flush()

		// Простой эхо-сервер для WebSocket
		go func() {
			defer conn.Close()
			for {
				buf := make([]byte, 1024)
				n, err := conn.Read(buf)
				if err != nil {
					break
				}
				conn.Write(buf[:n]) // Отправляем данные обратно клиенту
			}
		}()

		return true // Запрос обработан плагином
	}
	return false // Запрос не обработан плагином
}

// NewPlugin создает новый экземпляр плагина
func NewPlugin() core.Plugin {
	return &WSSPlugin{}
}
