package main

import (
	"GubinNET/core"
	"GubinNET/plugins/wss_plugin"
)

// Exported function to create a new plugin instance
func NewPlugin() core.Plugin {
	return wss_plugin.NewPlugin()
}
