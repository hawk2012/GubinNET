package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// HTMLHandler handles static HTML file serving
type HTMLHandler struct {
	BaseDir string
}

// NewHTMLHandler creates a new HTML handler
func NewHTMLHandler(baseDir string) *HTMLHandler {
	return &HTMLHandler{
		BaseDir: baseDir,
	}
}

// ServeHTTP handles HTML file requests
func (hh *HTMLHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Sanitize the path to prevent directory traversal
	sanitizedPath := filepath.Clean(r.URL.Path)
	
	// Ensure the path is within our allowed directory
	absolutePath := filepath.Join(hh.BaseDir, sanitizedPath)
	absoluteBase, _ := filepath.Abs(hh.BaseDir)
	absoluteFile, _ := filepath.Abs(absolutePath)
	
	if !strings.HasPrefix(absoluteFile, absoluteBase) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// If the path is a directory, look for index.html
	if info, err := os.Stat(absolutePath); err == nil && info.IsDir() {
		indexPath := filepath.Join(absolutePath, "index.html")
		if _, err := os.Stat(indexPath); err == nil {
			absolutePath = indexPath
		} else {
			// Check for other common index files
			possibleIndexes := []string{"index.htm", "default.html", "default.htm"}
			found := false
			for _, indexFile := range possibleIndexes {
				indexPath := filepath.Join(absolutePath, indexFile)
				if _, err := os.Stat(indexPath); err == nil {
					absolutePath = indexPath
					found = true
					break
				}
			}
			if !found {
				http.Error(w, "Directory listing not allowed", http.StatusForbidden)
				return
			}
		}
	}

	// If no extension is provided, try to find an HTML file
	if filepath.Ext(absolutePath) == "" {
		// Try adding .html extension
		htmlPath := absolutePath + ".html"
		if _, err := os.Stat(htmlPath); err == nil {
			absolutePath = htmlPath
		} else {
			// Try other extensions
			possibleExts := []string{".htm", ".shtml", ".xhtml"}
			found := false
			for _, ext := range possibleExts {
				altPath := absolutePath + ext
				if _, err := os.Stat(altPath); err == nil {
					absolutePath = altPath
					found = true
					break
				}
			}
			if !found {
				http.Error(w, "File not found", http.StatusNotFound)
				return
			}
		}
	}

	// Check if the file exists
	if _, err := os.Stat(absolutePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Security: validate the file path
	if !hh.isValidHTMLFile(absolutePath) {
		http.Error(w, "Invalid file", http.StatusForbidden)
		return
	}

	// Serve the file
	http.ServeFile(w, r, absolutePath)
}

// isValidHTMLFile checks if the file is a valid HTML file
func (hh *HTMLHandler) isValidHTMLFile(filePath string) bool {
	// Check file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	allowedExtensions := []string{".html", ".htm", ".shtml", ".xhtml", ".css", ".js", ".json", 
		".xml", ".txt", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot"}
	
	for _, allowedExt := range allowedExtensions {
		if ext == allowedExt {
			return true
		}
	}
	
	return false
}

// IsValidHTMLPath checks if the path is valid for HTML serving
func (hh *HTMLHandler) IsValidHTMLPath(path string) bool {
	// Prevent access to system files or sensitive directories
	normalizedPath := filepath.Clean(path)
	
	// Check for dangerous patterns
	dangerousPatterns := []string{
		"../", "..\\", "/etc/", "/proc/", "/sys/", "/dev/",
		"~/.ssh/", "/root/.ssh/", "/home/",
		".git/", ".svn/", ".hg/", // Version control directories
		"node_modules/",           // Node modules
		"vendor/",                // PHP Composer vendor
		"composer.json", "composer.lock", // PHP config files
		"package.json", "package-lock.json", // Node config files
		".env", ".config",         // Configuration files
	}
	
	for _, pattern := range dangerousPatterns {
		if strings.Contains(normalizedPath, pattern) {
			return false
		}
	}
	
	return true
}

// GetFileContentType returns the content type for a file
func (hh *HTMLHandler) GetFileContentType(filePath string) string {
	// Get the file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	
	// Map extensions to content types
	contentTypes := map[string]string{
		".html": "text/html; charset=utf-8",
		".htm":  "text/html; charset=utf-8",
		".css":  "text/css; charset=utf-8",
		".js":   "application/javascript",
		".json": "application/json; charset=utf-8",
		".xml":  "application/xml; charset=utf-8",
		".txt":  "text/plain; charset=utf-8",
		".svg":  "image/svg+xml",
		".png":  "image/png",
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".gif":  "image/gif",
		".ico":  "image/x-icon",
		".woff": "font/woff",
		".woff2": "font/woff2",
		".ttf":  "font/ttf",
		".eot":  "application/vnd.ms-fontobject",
	}
	
	if contentType, exists := contentTypes[ext]; exists {
		return contentType
	}
	
	// Default to text/html for HTML-related extensions
	if ext == ".shtml" || ext == ".xhtml" {
		return "text/html; charset=utf-8"
	}
	
	// For unknown files, use generic detection
	return "application/octet-stream"
}

// FileExists checks if a file exists in the HTML directory
func (hh *HTMLHandler) FileExists(path string) bool {
	absolutePath := filepath.Join(hh.BaseDir, filepath.Clean(path))
	
	if _, err := os.Stat(absolutePath); os.IsNotExist(err) {
		return false
	}
	
	return true
}

// ListDirectory lists files in a directory (with restrictions)
func (hh *HTMLHandler) ListDirectory(dirPath string) ([]os.FileInfo, error) {
	absolutePath := filepath.Join(hh.BaseDir, filepath.Clean(dirPath))
	
	// Validate the path
	if !hh.IsValidHTMLPath(absolutePath) {
		return nil, os.ErrPermission
	}
	
	// Check if it's actually a directory
	info, err := os.Stat(absolutePath)
	if err != nil {
		return nil, err
	}
	
	if !info.IsDir() {
		return nil, os.ErrInvalid
	}
	
	// Read directory contents
	files, err := os.ReadDir(absolutePath)
	if err != nil {
		return nil, err
	}
	
	// Convert to FileInfo slice, filtering out sensitive files
	var validFiles []os.FileInfo
	for _, file := range files {
		fileInfo, err := file.Info()
		if err != nil {
			continue
		}
		
		// Skip hidden files and sensitive files
		if strings.HasPrefix(file.Name(), ".") {
			continue
		}
		
		// Skip sensitive file extensions
		ext := strings.ToLower(filepath.Ext(file.Name()))
		if ext == ".env" || ext == ".config" || ext == ".log" {
			continue
		}
		
		validFiles = append(validFiles, fileInfo)
	}
	
	return validFiles, nil
}