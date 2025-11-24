package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PHPHandler handles PHP file execution
type PHPHandler struct {
	BaseDir string
}

// NewPHPHandler creates a new PHP handler
func NewPHPHandler(baseDir string) *PHPHandler {
	return &PHPHandler{
		BaseDir: baseDir,
	}
}

// ServeHTTP handles PHP file requests
func (ph *PHPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Sanitize the path to prevent directory traversal
	sanitizedPath := filepath.Clean(r.URL.Path)
	
	// Ensure the path is within our allowed directory
	absolutePath := filepath.Join(ph.BaseDir, sanitizedPath)
	absoluteBase, _ := filepath.Abs(ph.BaseDir)
	absoluteFile, _ := filepath.Abs(absolutePath)
	
	if !strings.HasPrefix(absoluteFile, absoluteBase) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	
	// Check if file exists and is a PHP file
	if !strings.HasSuffix(absolutePath, ".php") {
		// Try adding .php extension if it doesn't exist
		phpPath := absolutePath + ".php"
		if _, err := os.Stat(phpPath); err == nil {
			absolutePath = phpPath
		} else {
			http.Error(w, "Not a PHP file", http.StatusBadRequest)
			return
		}
	} else {
		if _, err := os.Stat(absolutePath); os.IsNotExist(err) {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
	}

	// Security: validate the file path
	if !ph.isValidPHPFile(absolutePath) {
		http.Error(w, "Invalid file", http.StatusForbidden)
		return
	}

	// Execute the PHP file
	cmd := exec.Command("php", absolutePath)
	
	// Set environment variables that might be needed by PHP
	cmd.Env = append(os.Environ(),
		"REQUEST_METHOD="+r.Method,
		"REQUEST_URI="+r.URL.RequestURI(),
		"QUERY_STRING="+r.URL.RawQuery,
		"HTTP_HOST="+r.Host,
		"HTTP_USER_AGENT="+r.UserAgent(),
		"HTTP_ACCEPT="+r.Header.Get("Accept"),
		"HTTP_ACCEPT_LANGUAGE="+r.Header.Get("Accept-Language"),
		"HTTP_ACCEPT_ENCODING="+r.Header.Get("Accept-Encoding"),
		"HTTP_CONNECTION="+r.Header.Get("Connection"),
		"REMOTE_ADDR="+getRealIP(r),
	)
	
	// Capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "PHP execution error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set appropriate content type based on output
	contentType := http.DetectContentType(output)
	if contentType == "text/plain; charset=utf-8" {
		// If it looks like HTML, set as text/html
		outputStr := string(output)
		if strings.Contains(strings.ToLower(outputStr), "<html") || 
		   strings.Contains(strings.ToLower(outputStr), "<head") || 
		   strings.Contains(strings.ToLower(outputStr), "<body") {
			contentType = "text/html; charset=utf-8"
		} else {
			contentType = "text/html; charset=utf-8" // Default to HTML for PHP output
		}
	}
	
	w.Header().Set("Content-Type", contentType)
	w.Write(output)
}

// isValidPHPFile checks if the file is a valid PHP file
func (ph *PHPHandler) isValidPHPFile(filePath string) bool {
	// Check file extension
	if !strings.HasSuffix(strings.ToLower(filePath), ".php") {
		return false
	}
	
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	}
	
	// Additional validation could be added here
	// For example, checking for specific PHP tags or content
	
	return true
}

// IsValidPHPPath checks if the path is valid for PHP execution
func (ph *PHPHandler) IsValidPHPPath(path string) bool {
	// Prevent access to system files or sensitive directories
	normalizedPath := filepath.Clean(path)
	
	// Check for dangerous patterns
	dangerousPatterns := []string{
		"../", "..\\", "/etc/", "/proc/", "/sys/", "/dev/",
		"~/.ssh/", "/root/.ssh/", "/home/",
	}
	
	for _, pattern := range dangerousPatterns {
		if strings.Contains(normalizedPath, pattern) {
			return false
		}
	}
	
	return true
}

// ExecutePHP executes a PHP script and returns the output
func (ph *PHPHandler) ExecutePHP(scriptPath string) ([]byte, error) {
	// Validate the script path
	if !ph.isValidPHPFile(scriptPath) {
		return nil, fmt.Errorf("invalid PHP file: %s", scriptPath)
	}
	
	// Execute the PHP file
	cmd := exec.Command("php", scriptPath)
	output, err := cmd.CombinedOutput()
	
	return output, err
}

// GetPHPInfo returns PHP configuration information
func (ph *PHPHandler) GetPHPInfo() (string, error) {
	cmd := exec.Command("php", "--version")
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		return "", err
	}
	
	return string(output), nil
}