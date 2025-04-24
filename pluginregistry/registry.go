package pluginregistry

import (
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"strings"

	"GubinNET/core" // Импортируем новый пакет core
)

func LoadPlugins(pluginDir string) error {
	err := filepath.Walk(pluginDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".so") {
			p, err := plugin.Open(path)
			if err != nil {
				return fmt.Errorf("failed to load plugin %s: %v", path, err)
			}

			symPlugin, err := p.Lookup("NewPlugin")
			if err != nil {
				return fmt.Errorf("plugin %s doesn't have NewPlugin function", path)
			}

			newPluginFunc, ok := symPlugin.(func() core.Plugin)
			if !ok {
				return fmt.Errorf("invalid NewPlugin signature in %s", path)
			}

			pluginInstance := newPluginFunc()
			core.RegisterPlugin(pluginInstance)
		}
		return nil
	})
	return err
}
