package plugins

import (
	"your_project_path/main"
)

// RegisterWSSPlugin регистрирует плагин WSS
func RegisterWSSPlugin() {
	main.RegisterPlugin(&WSSPlugin{})
}

// RegisterExamplePlugin регистрирует пример плагина
func RegisterExamplePlugin() {
	main.RegisterPlugin(&ExamplePlugin{})
}
