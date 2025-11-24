package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DotNetHandler handles .NET application execution
type DotNetHandler struct {
	BaseDir    string
	Proxy      *httputil.ReverseProxy
	AppProcess *os.Process
	AppPort    string
}

// NewDotNetHandler creates a new .NET handler
func NewDotNetHandler(baseDir string) *DotNetHandler {
	return &DotNetHandler{
		BaseDir: baseDir,
	}
}

// ServeHTTP handles .NET application requests
func (dh *DotNetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Determine the .NET application path
	appPath := filepath.Join(dh.BaseDir, filepath.Clean(r.URL.Path))
	
	// Check if this is a request to run a .NET application
	if strings.HasSuffix(appPath, ".dll") || strings.HasSuffix(appPath, ".exe") {
		// Run the .NET application directly (this is simplified)
		dh.runDotNetApp(w, r, appPath)
		return
	}
	
	// Look for a .NET project in the requested path
	projectPath := dh.findDotNetProject(filepath.Dir(appPath))
	if projectPath == "" {
		http.Error(w, ".NET project not found", http.StatusNotFound)
		return
	}
	
	// For this implementation, we'll assume the .NET app is already running on a specific port
	// In a real implementation, you'd start the app and proxy requests to it
	
	// Check if we have an active proxy connection
	if dh.Proxy == nil {
		// Try to start the .NET application
		if err := dh.startDotNetApp(projectPath); err != nil {
			http.Error(w, "Failed to start .NET application: "+err.Error(), http.StatusInternalServerError)
			return
		}
		
		// Wait a bit for the app to start
		time.Sleep(2 * time.Second)
	}
	
	// Proxy the request to the running .NET application
	if dh.Proxy != nil {
		dh.Proxy.ServeHTTP(w, r)
		return
	}
	
	http.Error(w, "Unable to connect to .NET application", http.StatusInternalServerError)
}

// runDotNetApp runs a .NET application directly
func (dh *DotNetHandler) runDotNetApp(w http.ResponseWriter, r *http.Request, appPath string) {
	// Validate the file path
	if !dh.isValidDotNetFile(appPath) {
		http.Error(w, "Invalid .NET file", http.StatusForbidden)
		return
	}
	
	// Execute the .NET application
	cmd := exec.Command("dotnet", appPath)
	
	// Set environment variables
	cmd.Env = append(os.Environ(),
		"ASPNETCORE_ENVIRONMENT=Production",
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
		http.Error(w, "Failed to execute .NET application: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Set content type and write output
	contentType := http.DetectContentType(output)
	if contentType == "text/plain; charset=utf-8" {
		contentType = "text/html; charset=utf-8" // Default for web responses
	}
	
	w.Header().Set("Content-Type", contentType)
	w.Write(output)
}

// startDotNetApp starts a .NET application
func (dh *DotNetHandler) startDotNetApp(projectPath string) error {
	// Find a free port for the application
	port := dh.getFreePort()
	
	// Build the .NET application
	buildCmd := exec.Command("dotnet", "build", projectPath)
	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("build failed: %v, output: %s", err, string(buildOutput))
	}
	
	// Run the .NET application
	runCmd := exec.Command("dotnet", "run", "--project", projectPath, "--urls", "http://localhost:"+port)
	
	// Set environment variables
	runCmd.Env = append(os.Environ(),
		"ASPNETCORE_ENVIRONMENT=Production",
		"ASPNETCORE_URLS=http://localhost:"+port,
	)
	
	// Start the process
	err = runCmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start .NET application: %v", err)
	}
	
	// Store the process reference
	dh.AppProcess = runCmd.Process
	dh.AppPort = port
	
	// Create a reverse proxy to the running application
	target, _ := url.Parse("http://localhost:" + port)
	dh.Proxy = httputil.NewSingleHostReverseProxy(target)
	
	return nil
}

// findDotNetProject finds a .NET project file in the given directory
func (dh *DotNetHandler) findDotNetProject(dir string) string {
	// Look for common .NET project files
	extensions := []string{".csproj", ".fsproj", ".vbproj"}
	
	// Walk up the directory tree if needed
	currentDir := dir
	for {
		// Read directory contents
		files, err := os.ReadDir(currentDir)
		if err != nil {
			break
		}
		
		// Look for project files
		for _, file := range files {
			if file.IsDir() {
				continue
			}
			
			for _, ext := range extensions {
				if strings.HasSuffix(strings.ToLower(file.Name()), ext) {
					return filepath.Join(currentDir, file.Name())
				}
			}
		}
		
		// Move up one directory level
		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir {
			// We've reached the root
			break
		}
		currentDir = parentDir
	}
	
	return ""
}

// isValidDotNetFile checks if the file is a valid .NET file
func (dh *DotNetHandler) isValidDotNetFile(filePath string) bool {
	// Check file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	validExtensions := []string{".dll", ".exe", ".csproj", ".fsproj", ".vbproj"}
	
	for _, validExt := range validExtensions {
		if ext == validExt {
			return true
		}
	}
	
	return false
}

// getFreePort finds an available port
func (dh *DotNetHandler) getFreePort() string {
	// This is a simplified implementation
	// In a real system, you'd properly check for free ports
	// For now, we'll use a fixed port or increment from a base
	return "5000" // Default ASP.NET Core port
}

// GetDotNetVersion returns .NET version information
func (dh *DotNetHandler) GetDotNetVersion() (string, error) {
	cmd := exec.Command("dotnet", "--version")
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		return "", err
	}
	
	return string(output), nil
}

// RunDotNetCommand executes a dotnet command
func (dh *DotNetHandler) RunDotNetCommand(args ...string) ([]byte, error) {
	cmd := exec.Command("dotnet", args...)
	output, err := cmd.CombinedOutput()
	
	return output, err
}

// PublishDotNetApp publishes a .NET application
func (dh *DotNetHandler) PublishDotNetApp(projectPath, outputPath string) error {
	args := []string{"publish", projectPath, "--output", outputPath, "--configuration", "Release"}
	
	cmd := exec.Command("dotnet", args...)
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		return fmt.Errorf("publish failed: %v, output: %s", err, string(output))
	}
	
	return nil
}

// StopDotNetApp stops the currently running .NET application
func (dh *DotNetHandler) StopDotNetApp() error {
	if dh.AppProcess != nil {
		err := dh.AppProcess.Kill()
		if err != nil {
			return err
		}
		dh.AppProcess = nil
		dh.Proxy = nil
		dh.AppPort = ""
	}
	
	return nil
}

// IsValidDotNetPath checks if the path is valid for .NET execution
func (dh *DotNetHandler) IsValidDotNetPath(path string) bool {
	// Prevent access to system files or sensitive directories
	normalizedPath := filepath.Clean(path)
	
	// Check for dangerous patterns
	dangerousPatterns := []string{
		"../", "..\\", "/etc/", "/proc/", "/sys/", "/dev/",
		"~/.ssh/", "/root/.ssh/", "/home/",
		"bin/", "obj/", // Prevent access to build directories
	}
	
	for _, pattern := range dangerousPatterns {
		if strings.Contains(normalizedPath, pattern) {
			return false
		}
	}
	
	return true
}