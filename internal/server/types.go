package server

import (
	"context"
	"net/http"
	"sync"

	"gubinnet/internal/config"
	"gubinnet/internal/logging"
	"gubinnet/internal/modules"
	"gubinnet/internal/security"
)

type Server interface {
	Start() error
	Shutdown(ctx context.Context) error
	Reload(config *config.Config) error
}

type GubinServer struct {
	config   *config.Config
	logger   *logging.Logger
	antiDDoS *security.AntiDDoS
	cache    *FileCache
	modules  *modules.Manager
	servers  map[string]*http.Server
	mu       sync.RWMutex
}
