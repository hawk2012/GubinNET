package utils

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// FileExists проверяет существует ли файл
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// IsDir проверяет является ли путь директорией
func IsDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// EnsureDir создает директорию если она не существует
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// GetFileSize возвращает размер файла
func GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// GetFileModTime возвращает время модификации файла
func GetFileModTime(path string) (time.Time, error) {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// CalculateFileHash вычисляет MD5 хеш файла
func CalculateFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// GetMimeType возвращает MIME тип файла
func GetMimeType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	mimeType := mime.TypeByExtension(ext)

	if mimeType == "" {
		// Пробуем определить по содержимому
		file, err := os.Open(path)
		if err != nil {
			return "application/octet-stream"
		}
		defer file.Close()

		buffer := make([]byte, 512)
		_, err = file.Read(buffer)
		if err != nil {
			return "application/octet-stream"
		}

		mimeType = http.DetectContentType(buffer)
	}

	return mimeType
}

// CopyFile копирует файл
func CopyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	// Создаем директорию назначения если нужно
	if err := EnsureDir(filepath.Dir(dst)); err != nil {
		return err
	}

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

// SafeWriteFile безопасно записывает файл (через временный файл)
func SafeWriteFile(path string, data []byte) error {
	// Создаем временный файл
	tempPath := path + ".tmp"

	if err := os.WriteFile(tempPath, data, 0644); err != nil {
		return err
	}

	// Переименовываем атомарно
	return os.Rename(tempPath, path)
}

// ListFiles возвращает список файлов в директории
func ListFiles(dir string, recursive bool) ([]string, error) {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			files = append(files, path)
		} else if path != dir && !recursive {
			return filepath.SkipDir
		}

		return nil
	})

	return files, err
}

// FindFilesByPattern ищет файлы по шаблону
func FindFilesByPattern(dir, pattern string) ([]string, error) {
	return filepath.Glob(filepath.Join(dir, pattern))
}

// GetDiskUsage возвращает использование диска для пути
func GetDiskUsage(path string) (used, free, total int64, err error) {
	var stat syscall.Statfs_t

	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, 0, err
	}

	// Расчет в байтах
	total = int64(stat.Blocks) * int64(stat.Bsize)
	free = int64(stat.Bfree) * int64(stat.Bsize)
	used = total - free

	return used, free, total, nil
}

// HumanizeBytes преобразует байты в человеко-читаемый формат
func HumanizeBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// CleanPath очищает путь от лишних элементов
func CleanPath(path string) string {
	return filepath.Clean(path)
}

// RelativePath возвращает относительный путь
func RelativePath(base, target string) (string, error) {
	return filepath.Rel(base, target)
}
