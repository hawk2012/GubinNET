package plugins

import (
	"GubinNET/core"
)

func init() {
	// Регистрация WebSocket-плагина
	core.RegisterPlugin(NewPlugin())
}
