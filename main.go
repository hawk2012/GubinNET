package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
)

// GubinNET is a web server that supports multiple technologies
type GubinNET struct {
	Router        *mux.Router
	Port          string
	Security      *SecurityManager
	RewriteEngine *RewriteEngine
	HTMLHandler   *HTMLHandler
	PHPHandler    *PHPHandler
	NodeJSHandler *NodeJSHandler
	DotNetHandler *DotNetHandler
	Config        Config
}

// NewGubinNET creates a new instance of the GubinNET server
func NewGubinNET(config Config) *GubinNET {
	router := mux.NewRouter()
	
	// Create security manager
	security := NewSecurityManager(config)
	
	// Create rewrite engine and load rules
	rewriteEngine := NewRewriteEngine()
	rewriteEngine.LoadRulesFromConfig(config)
	
	// Create handlers for different technologies
	htmlHandler := NewHTMLHandler(config.PublicDir)
	phpHandler := NewPHPHandler(config.PublicDir)
	nodeJSHandler := NewNodeJSHandler(config.PublicDir)
	dotNetHandler := NewDotNetHandler(config.PublicDir)
	
	return &GubinNET{
		Router:        router,
		Port:          config.Port,
		Security:      security,
		RewriteEngine: rewriteEngine,
		HTMLHandler:   htmlHandler,
		PHPHandler:    phpHandler,
		NodeJSHandler: nodeJSHandler,
		DotNetHandler: dotNetHandler,
		Config:        config,
	}
}

// SetupRoutes configures all routes for the server
func (g *GubinNET) SetupRoutes() {
	// Apply security middleware first
	g.Router.Use(g.Security.Middleware)
	
	// Apply rewrite middleware
	g.Router.Use(g.RewriteEngine.Middleware)
	
	// Setup routes for different technologies based on file extensions
	g.Router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Determine handler based on file extension or path
		path := r.URL.Path
		
		switch {
		case hasExtension(path, ".php"):
			g.PHPHandler.ServeHTTP(w, r)
		case hasExtension(path, ".js") || hasExtension(path, ".mjs"):
			g.NodeJSHandler.ServeHTTP(w, r)
		case hasDotNetExtension(path):
			g.DotNetHandler.ServeHTTP(w, r)
		default:
			// For other requests, try HTML handler
			g.HTMLHandler.ServeHTTP(w, r)
		}
	})
}

// hasExtension checks if a path has a specific extension
func hasExtension(path, ext string) bool {
	return len(path) >= len(ext) && path[len(path)-len(ext):] == ext
}

// hasDotNetExtension checks if a path has a .NET-related extension
func hasDotNetExtension(path string) bool {
	dotNetExts := []string{".dll", ".exe", ".csproj", ".fsproj", ".vbproj"}
	for _, ext := range dotNetExts {
		if hasExtension(path, ext) {
			return true
		}
	}
	return false
}

// Start the server
func (g *GubinNET) Start() {
	fmt.Printf("GubinNET server starting on port %s\n", g.Port)
	
	// Create public directory if it doesn't exist
	os.MkdirAll(g.Config.PublicDir, 0755)
	
	// Setup routes
	g.SetupRoutes()
	
	// Start server with timeout
	srv := &http.Server{
		Addr:         ":" + g.Port,
		Handler:      g.Router,
		ReadTimeout:  time.Duration(g.Config.Timeout) * time.Second,
		WriteTimeout: time.Duration(g.Config.Timeout) * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	fmt.Printf("GubinNET server initialized with security features:\n")
	fmt.Printf("- Anti-DDoS protection: %t\n", g.Config.AntiDDoS.Enabled)
	fmt.Printf("- Bot protection: enabled\n")
	fmt.Printf("- XSS protection: enabled\n")
	fmt.Printf("- mod_rewrite: enabled\n")
	fmt.Printf("- Supported technologies: HTML, PHP, Node.js, .NET\n")
	
	log.Fatal(srv.ListenAndServe())
}

func main() {
	// Load configuration
	config, err := LoadConfig("config.json")
	if err != nil {
		log.Printf("Error loading config: %v, using defaults", err)
		config = DefaultConfig()
	}
	
	// Create new GubinNET server instance
	server := NewGubinNET(config)
	
	// Start the server
	server.Start()
}