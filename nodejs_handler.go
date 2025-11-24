package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// NodeJSHandler handles Node.js file execution
type NodeJSHandler struct {
	BaseDir string
}

// NewNodeJSHandler creates a new Node.js handler
func NewNodeJSHandler(baseDir string) *NodeJSHandler {
	return &NodeJSHandler{
		BaseDir: baseDir,
	}
}

// ServeHTTP handles Node.js file requests
func (nh *NodeJSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Sanitize the path to prevent directory traversal
	sanitizedPath := filepath.Clean(r.URL.Path)
	
	// Ensure the path is within our allowed directory
	absolutePath := filepath.Join(nh.BaseDir, sanitizedPath)
	absoluteBase, _ := filepath.Abs(nh.BaseDir)
	absoluteFile, _ := filepath.Abs(absolutePath)
	
	if !strings.HasPrefix(absoluteFile, absoluteBase) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	
	// Check if file exists and is a JavaScript file
	if !strings.HasSuffix(absolutePath, ".js") && !strings.HasSuffix(absolutePath, ".mjs") {
		http.Error(w, "Not a Node.js file", http.StatusBadRequest)
		return
	}
	
	if _, err := os.Stat(absolutePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Security: validate the file path
	if !nh.isValidNodeJSFile(absolutePath) {
		http.Error(w, "Invalid file", http.StatusForbidden)
		return
	}

	// Execute the Node.js file
	cmd := exec.Command("node", absolutePath)
	
	// Set environment variables that might be needed by Node.js
	cmd.Env = append(os.Environ(),
		"NODE_ENV=production",
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
		http.Error(w, "Node.js execution error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set appropriate content type based on output
	contentType := http.DetectContentType(output)
	if contentType == "text/plain; charset=utf-8" {
		// If output looks like JSON, set as application/json
		outputStr := string(output)
		if strings.HasPrefix(strings.TrimSpace(outputStr), "{") || 
		   strings.HasPrefix(strings.TrimSpace(outputStr), "[") {
			contentType = "application/json; charset=utf-8"
		} else {
			contentType = "text/html; charset=utf-8" // Default for Node.js web responses
		}
	}
	
	w.Header().Set("Content-Type", contentType)
	w.Write(output)
}

// isValidNodeJSFile checks if the file is a valid Node.js file
func (nh *NodeJSHandler) isValidNodeJSFile(filePath string) bool {
	// Check file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext != ".js" && ext != ".mjs" {
		return false
	}
	
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	}
	
	// Additional validation could be added here
	// For example, checking for specific Node.js patterns or content
	
	return true
}

// IsValidNodeJSPath checks if the path is valid for Node.js execution
func (nh *NodeJSHandler) IsValidNodeJSPath(path string) bool {
	// Prevent access to system files or sensitive directories
	normalizedPath := filepath.Clean(path)
	
	// Check for dangerous patterns
	dangerousPatterns := []string{
		"../", "..\\", "/etc/", "/proc/", "/sys/", "/dev/",
		"~/.ssh/", "/root/.ssh/", "/home/",
		"node_modules", // Prevent access to node_modules for security
	}
	
	for _, pattern := range dangerousPatterns {
		if strings.Contains(normalizedPath, pattern) {
			return false
		}
	}
	
	return true
}

// ExecuteNodeJS executes a Node.js script and returns the output
func (nh *NodeJSHandler) ExecuteNodeJS(scriptPath string) ([]byte, error) {
	// Validate the script path
	if !nh.isValidNodeJSFile(scriptPath) {
		return nil, fmt.Errorf("invalid Node.js file: %s", scriptPath)
	}
	
	// Execute the Node.js file
	cmd := exec.Command("node", scriptPath)
	output, err := cmd.CombinedOutput()
	
	return output, err
}

// GetNodeJSVersion returns Node.js version information
func (nh *NodeJSHandler) GetNodeJSVersion() (string, error) {
	cmd := exec.Command("node", "--version")
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		return "", err
	}
	
	return string(output), nil
}

// CreateExpressServer creates a simple Express-like server for Node.js files
func (nh *NodeJSHandler) CreateExpressServer(scriptPath string) error {
	// This is a simplified approach - in reality, Node.js applications
	// would typically run separately and GubinNET would proxy to them
	
	// For now, we'll just validate that the script can run
	if _, err := nh.ExecuteNodeJS(scriptPath); err != nil {
		return fmt.Errorf("Node.js script is not executable: %v", err)
	}
	
	return nil
}

// RunNPMCommand executes an npm command in the specified directory
func (nh *NodeJSHandler) RunNPMCommand(dir, command string) ([]byte, error) {
	// Change to the specified directory
	originalDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	
	if err := os.Chdir(dir); err != nil {
		return nil, err
	}
	
	// Restore original directory when done
	defer os.Chdir(originalDir)
	
	// Execute the npm command
	cmd := exec.Command("npm", strings.Split(command, " ")...)
	output, err := cmd.CombinedOutput()
	
	return output, err
}