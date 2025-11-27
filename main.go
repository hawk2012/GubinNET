package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// GubinNET is a web server that supports multiple technologies
type GubinNET struct {
	Router             *mux.Router
	Port               string
	Security           *SecurityManager
	RewriteEngine      *RewriteEngine
	HTMLHandler        *HTMLHandler
	PHPHandler         *PHPHandler
	NodeJSHandler      *NodeJSHandler
	DotNetHandler      *DotNetHandler
	Config             Config
	VirtualHostManager *VirtualHostManager
}

// NewGubinNET creates a new instance of the GubinNET server
func NewGubinNET(config Config) *GubinNET {
	router := mux.NewRouter()
	
	// Create security manager
	security := NewSecurityManager(config)
	
	// Create rewrite engine and load rules
	rewriteEngine := NewRewriteEngine()
	rewriteEngine.LoadRulesFromConfig(config)
	
	// Connect to database and create virtual host manager
	var virtualHostManager *VirtualHostManager
	if config.Database.Host != "" {
		db, err := config.ConnectDB()
		if err != nil {
			log.Printf("Failed to connect to database: %v", err)
			log.Println("Running in single-host mode without virtual hosts")
			// Create handlers with default public directory
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
				VirtualHostManager: nil,
			}
		}
		virtualHostManager = NewVirtualHostManager(db)
	} else {
		log.Println("No database configuration found, running in single-host mode")
		// Create handlers with default public directory
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
			VirtualHostManager: nil,
		}
	}
	
	// Get virtual host for default configuration (if any)
	defaultVirtualHost, err := virtualHostManager.GetVirtualHostByDomain("") // Empty domain as default
	if err != nil {
		// If no default virtual host is found, use the config's public_dir
		log.Println("No default virtual host found, using config public_dir")
	} else {
		config.PublicDir = defaultVirtualHost.PublicDir
	}
	
	// Create handlers for different technologies with default or first virtual host directory
	htmlHandler := NewHTMLHandler(config.PublicDir)
	phpHandler := NewPHPHandler(config.PublicDir)
	nodeJSHandler := NewNodeJSHandler(config.PublicDir)
	dotNetHandler := NewDotNetHandler(config.PublicDir)
	
	return &GubinNET{
		Router:             router,
		Port:               config.Port,
		Security:           security,
		RewriteEngine:      rewriteEngine,
		HTMLHandler:        htmlHandler,
		PHPHandler:         phpHandler,
		NodeJSHandler:      nodeJSHandler,
		DotNetHandler:      dotNetHandler,
		Config:             config,
		VirtualHostManager: virtualHostManager,
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
		// Determine the virtual host based on the request host
		var virtualHost *VirtualHost
		var htmlHandler *HTMLHandler
		var phpHandler *PHPHandler
		var nodeJSHandler *NodeJSHandler
		var dotNetHandler *DotNetHandler
		
		if g.VirtualHostManager != nil {
			// Extract domain from request (remove port if present)
			host := r.Host
			if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
				host = host[:colonIndex]
			}
			
			// Look up virtual host configuration from database
			vh, err := g.VirtualHostManager.GetVirtualHostByDomain(host)
			if err != nil {
				log.Printf("Virtual host not found for domain %s: %v", host, err)
				// Fall back to default configuration
				virtualHost = nil
				htmlHandler = g.HTMLHandler
				phpHandler = g.PHPHandler
				nodeJSHandler = g.NodeJSHandler
				dotNetHandler = g.DotNetHandler
			} else {
				virtualHost = vh
				// Create new handlers for this virtual host's directory
				htmlHandler = NewHTMLHandler(virtualHost.PublicDir)
				phpHandler = NewPHPHandler(virtualHost.PublicDir)
				nodeJSHandler = NewNodeJSHandler(virtualHost.PublicDir)
				dotNetHandler = NewDotNetHandler(virtualHost.PublicDir)
			}
		} else {
			// Use default configuration
			virtualHost = nil
			htmlHandler = g.HTMLHandler
			phpHandler = g.PHPHandler
			nodeJSHandler = g.NodeJSHandler
			dotNetHandler = g.DotNetHandler
		}
		
		// Determine handler based on file extension or path
		path := r.URL.Path
		
		switch {
		case hasExtension(path, ".php"):
			phpHandler.ServeHTTP(w, r)
		case hasExtension(path, ".js") || hasExtension(path, ".mjs"):
			nodeJSHandler.ServeHTTP(w, r)
		case hasDotNetExtension(path):
			dotNetHandler.ServeHTTP(w, r)
		default:
			// For other requests, try HTML handler
			htmlHandler.ServeHTTP(w, r)
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
	// Load configuration from gubinnet.conf
	config, err := LoadConfig("gubinnet.conf")
	if err != nil {
		log.Printf("Error loading config from gubinnet.conf: %v, using defaults", err)
		config = DefaultConfig()
	}
	
	// Create new GubinNET server instance
	server := NewGubinNET(config)
	
	// Start the server
	server.Start()
}