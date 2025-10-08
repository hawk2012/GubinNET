package server

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type CacheEntry struct {
	content     []byte
	modTime     time.Time
	size        int64
	contentType string
	expiresAt   time.Time
}

type FileCache struct {
	entries map[string]*CacheEntry
	mu      sync.RWMutex
	ttl     time.Duration
}

func NewFileCache() *FileCache {
	return &FileCache{
		entries: make(map[string]*CacheEntry),
		ttl:     5 * time.Minute, // TTL 5 минут
	}
}

func (c *FileCache) Get(filePath string, fileInfo os.FileInfo) ([]byte, string, error) {
	c.mu.RLock()
	entry, exists := c.entries[filePath]
	c.mu.RUnlock()

	// Проверяем актуальность кэша
	if exists && time.Now().Before(entry.expiresAt) {
		if fileInfo.ModTime().Equal(entry.modTime) {
			return entry.content, entry.contentType, nil
		}
	}

	// Читаем файл
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, "", err
	}

	contentType := c.getContentType(filePath)

	// Сохраняем в кэш
	entry = &CacheEntry{
		content:     content,
		modTime:     fileInfo.ModTime(),
		size:        fileInfo.Size(),
		contentType: contentType,
		expiresAt:   time.Now().Add(c.ttl),
	}

	c.mu.Lock()
	c.entries[filePath] = entry
	c.mu.Unlock()

	return content, contentType, nil
}

func (c *FileCache) getContentType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".json":
		return "application/json"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".webp":
		return "image/webp"
	case ".txt":
		return "text/plain; charset=utf-8"
	case ".pdf":
		return "application/pdf"
	default:
		return "application/octet-stream"
	}
}

func (c *FileCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for path, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, path)
		}
	}
}

func (c *FileCache) StartCleanupWorker() {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			c.Cleanup()
		}
	}()
}
