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
	maxSize int64  // максимальный размер кэша в байтах
	maxItemSize int64 // максимальный размер одного элемента в байтах
	currentSize int64 // текущий размер кэша в байтах
}

func NewFileCache() *FileCache {
	return &FileCache{
		entries: make(map[string]*CacheEntry),
		ttl:     5 * time.Minute, // TTL 5 минут
		maxSize: 100 * 1024 * 1024, // 100MB максимальный размер кэша
		maxItemSize: 10 * 1024 * 1024, // 10MB максимальный размер одного файла
		currentSize: 0,
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

	// Проверяем размер файла перед кэшированием
	fileSize := int64(len(content))
	if fileSize > c.maxItemSize {
		return content, c.getContentType(filePath), nil // возвращаем файл без кэширования
	}

	contentType := c.getContentType(filePath)

	// Проверяем, умещается ли файл в кэш
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if c.currentSize + fileSize > c.maxSize {
		// Очищаем кэш, если он переполнен
		c.evictEntries(fileSize)
	}

	// Проверяем снова, умещается ли файл в кэш
	if c.currentSize + fileSize <= c.maxSize {
		// Сохраняем в кэш
		entry = &CacheEntry{
			content:     content,
			modTime:     fileInfo.ModTime(),
			size:        fileSize,
			contentType: contentType,
			expiresAt:   time.Now().Add(c.ttl),
		}

		c.entries[filePath] = entry
		c.currentSize += fileSize
	}

	return content, contentType, nil
}

// evictEntries удаляет старые записи из кэша, чтобы освободить место
func (c *FileCache) evictEntries(requiredSize int64) {
	// Простой алгоритм: удаляем записи, начиная с самых старых
	// В реальном приложении может использоваться LRU или другой алгоритм

	// Сначала удаляем устаревшие записи
	now := time.Now()
	for path, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, path)
			c.currentSize -= entry.size
		}
	}

	// Если все еще не хватает места, удаляем случайные записи
	// В реальном приложении стоит использовать более умный алгоритм
	for c.currentSize + requiredSize > c.maxSize {
		for path, entry := range c.entries {
			delete(c.entries, path)
			c.currentSize -= entry.size
			break // удаляем по одной записи за итерацию
		}
		// Если кэш пуст, выходим
		if len(c.entries) == 0 {
			break
		}
	}
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
			c.currentSize -= entry.size
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

// Count возвращает количество элементов в кэше
func (c *FileCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// GetCurrentSize возвращает текущий размер кэша в байтах
func (c *FileCache) GetCurrentSize() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentSize
}

// GetMaxSize возвращает максимальный размер кэша в байтах
func (c *FileCache) GetMaxSize() int64 {
	return c.maxSize
}
