package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
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
				Router:             router,
				Port:               config.Port,
				Security:           security,
				RewriteEngine:      rewriteEngine,
				HTMLHandler:        htmlHandler,
				PHPHandler:         phpHandler,
				NodeJSHandler:      nodeJSHandler,
				DotNetHandler:      dotNetHandler,
				Config:             config,
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
			Router:             router,
			Port:               config.Port,
			Security:           security,
			RewriteEngine:      rewriteEngine,
			HTMLHandler:        htmlHandler,
			PHPHandler:         phpHandler,
			NodeJSHandler:      nodeJSHandler,
			DotNetHandler:      dotNetHandler,
			Config:             config,
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

	// Health check endpoint
	g.Router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}).Methods("GET")

	// Setup API routes if virtual host manager is available
	if g.VirtualHostManager != nil {
		g.SetupAPIRoutes()
	}

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
		case HasExtension(path, ".php"):
			phpHandler.ServeHTTP(w, r)
		case HasExtension(path, ".js") || HasExtension(path, ".mjs"):
			nodeJSHandler.ServeHTTP(w, r)
		case IsDotNetExtension(path):
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

// SetupAPIRoutes configures API routes for virtual host management
func (g *GubinNET) SetupAPIRoutes() {
	api := g.Router.PathPrefix("/api/v1").Subrouter()

	// Virtual hosts API
	api.HandleFunc("/hosts", g.listVirtualHostsHandler).Methods("GET")
	api.HandleFunc("/hosts", g.createVirtualHostHandler).Methods("POST")
	api.HandleFunc("/hosts/{id}", g.getVirtualHostHandler).Methods("GET")
	api.HandleFunc("/hosts/{id}", g.updateVirtualHostHandler).Methods("PUT")
	api.HandleFunc("/hosts/{id}", g.deleteVirtualHostHandler).Methods("DELETE")
	api.HandleFunc("/hosts/{domain}/enable", g.enableVirtualHostHandler).Methods("POST")
	api.HandleFunc("/hosts/{domain}/disable", g.disableVirtualHostHandler).Methods("POST")

	// Nginx integration API
	api.HandleFunc("/nginx/sync", g.syncToNginxHandler).Methods("POST")
	api.HandleFunc("/nginx/config/{domain}", g.getNginxConfigHandler).Methods("GET")
	api.HandleFunc("/nginx/reload", g.reloadNginxHandler).Methods("POST")
	api.HandleFunc("/nginx/status", g.nginxStatusHandler).Methods("GET")
	api.HandleFunc("/nginx/test", g.testNginxConfigHandler).Methods("GET")
}

// API Handlers

func (g *GubinNET) listVirtualHostsHandler(w http.ResponseWriter, r *http.Request) {
	if g.VirtualHostManager == nil {
		http.Error(w, "Virtual host manager not available", http.StatusServiceUnavailable)
		return
	}

	hosts, err := g.VirtualHostManager.GetAllVirtualHostsIncludingDisabled()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hosts)
}

func (g *GubinNET) createVirtualHostHandler(w http.ResponseWriter, r *http.Request) {
	if g.VirtualHostManager == nil {
		http.Error(w, "Virtual host manager not available", http.StatusServiceUnavailable)
		return
	}

	var vh VirtualHost
	if err := json.NewDecoder(r.Body).Decode(&vh); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Set defaults
	if vh.Port == "" {
		vh.Port = "80"
	}

	if err := g.VirtualHostManager.CreateVirtualHost(&vh); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(vh)
}

func (g *GubinNET) getVirtualHostHandler(w http.ResponseWriter, r *http.Request) {
	if g.VirtualHostManager == nil {
		http.Error(w, "Virtual host manager not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	vh, err := g.VirtualHostManager.GetVirtualHostByID(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vh)
}

func (g *GubinNET) updateVirtualHostHandler(w http.ResponseWriter, r *http.Request) {
	if g.VirtualHostManager == nil {
		http.Error(w, "Virtual host manager not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	var vh VirtualHost
	if err := json.NewDecoder(r.Body).Decode(&vh); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	vh.ID = id
	if err := g.VirtualHostManager.UpdateVirtualHost(&vh); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vh)
}

func (g *GubinNET) deleteVirtualHostHandler(w http.ResponseWriter, r *http.Request) {
	if g.VirtualHostManager == nil {
		http.Error(w, "Virtual host manager not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := g.VirtualHostManager.DeleteVirtualHost(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (g *GubinNET) enableVirtualHostHandler(w http.ResponseWriter, r *http.Request) {
	if g.VirtualHostManager == nil {
		http.Error(w, "Virtual host manager not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	domain := vars["domain"]

	if err := g.VirtualHostManager.EnableVirtualHost(domain); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "enabled", "domain": domain})
}

func (g *GubinNET) disableVirtualHostHandler(w http.ResponseWriter, r *http.Request) {
	if g.VirtualHostManager == nil {
		http.Error(w, "Virtual host manager not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	domain := vars["domain"]

	if err := g.VirtualHostManager.DisableVirtualHost(domain); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "disabled", "domain": domain})
}

func (g *GubinNET) syncToNginxHandler(w http.ResponseWriter, r *http.Request) {
	if g.VirtualHostManager == nil {
		http.Error(w, "Virtual host manager not available", http.StatusServiceUnavailable)
		return
	}

	nginxHandler := NewNginxHandler()
	if err := nginxHandler.SyncFromDatabase(g.VirtualHostManager); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "synced"})
}

func (g *GubinNET) getNginxConfigHandler(w http.ResponseWriter, r *http.Request) {
	if g.VirtualHostManager == nil {
		http.Error(w, "Virtual host manager not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	domain := vars["domain"]

	vh, err := g.VirtualHostManager.GetVirtualHostByDomain(domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	nginxHandler := NewNginxHandler()
	config := nginxHandler.GenerateVirtualHostConfig(vh)

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(config))
}

func (g *GubinNET) reloadNginxHandler(w http.ResponseWriter, r *http.Request) {
	nginxHandler := NewNginxHandler()
	if err := nginxHandler.ReloadNginx(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
}

func (g *GubinNET) nginxStatusHandler(w http.ResponseWriter, r *http.Request) {
	nginxHandler := NewNginxHandler()
	status, err := nginxHandler.GetNginxStatus()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(status))
}

func (g *GubinNET) testNginxConfigHandler(w http.ResponseWriter, r *http.Request) {
	nginxHandler := NewNginxHandler()
	output, err := nginxHandler.TestConfig()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "output": output})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "output": output})
}

func main() {
	// CLI flags
	serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
	serverPort := serverCmd.String("port", "", "Server port (overrides config)")
	serverPublicDir := serverCmd.String("public", "", "Public directory (overrides config)")

	nginxCmd := flag.NewFlagSet("nginx", flag.ExitOnError)
	nginxSync := nginxCmd.Bool("sync", false, "Sync virtual hosts from database to nginx")
	nginxReload := nginxCmd.Bool("reload", false, "Reload nginx configuration")
	nginxTest := nginxCmd.Bool("test", false, "Test nginx configuration")
	nginxStatus := nginxCmd.Bool("status", false, "Show nginx status")
	nginxList := nginxCmd.Bool("list", false, "List nginx virtual hosts")

	hostsCmd := flag.NewFlagSet("hosts", flag.ExitOnError)
	hostsList := hostsCmd.Bool("list", false, "List all virtual hosts")
	hostsAdd := hostsCmd.Bool("add", false, "Add a new virtual host")
	hostsRemove := hostsCmd.Bool("remove", false, "Remove a virtual host")
	hostsEnable := hostsCmd.Bool("enable", false, "Enable a virtual host")
	hostsDisable := hostsCmd.Bool("disable", false, "Disable a virtual host")
	hostsDomain := hostsCmd.String("domain", "", "Domain name")
	hostsPublicDir := hostsCmd.String("public", "", "Public directory")
	hostsPort := hostsCmd.String("port", "80", "Port")
	hostsSSL := hostsCmd.Bool("ssl", false, "Enable SSL")
	hostsSSLCert := hostsCmd.String("cert", "", "SSL certificate path")
	hostsSSLKey := hostsCmd.String("key", "", "SSL key path")

	generateCmd := flag.NewFlagSet("generate", flag.ExitOnError)
	generateDomain := generateCmd.String("domain", "", "Domain name for nginx config")
	generateOutput := generateCmd.String("output", "", "Output file (default: stdout)")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		serverCmd.Parse(os.Args[2:])
		runServer(*serverPort, *serverPublicDir)
	case "nginx":
		nginxCmd.Parse(os.Args[2:])
		runNginxCommand(*nginxSync, *nginxReload, *nginxTest, *nginxStatus, *nginxList)
	case "hosts":
		hostsCmd.Parse(os.Args[2:])
		runHostsCommand(*hostsList, *hostsAdd, *hostsRemove, *hostsEnable, *hostsDisable,
			*hostsDomain, *hostsPublicDir, *hostsPort, *hostsSSL, *hostsSSLCert, *hostsSSLKey)
	case "generate":
		generateCmd.Parse(os.Args[2:])
		runGenerateCommand(*generateDomain, *generateOutput)
	case "help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("GubinNET - Advanced Go Web Server")
	fmt.Println("\nUsage:")
	fmt.Println("  gubinnet <command> [options]")
	fmt.Println("\nCommands:")
	fmt.Println("  server   Start the web server")
	fmt.Println("  nginx    Manage nginx integration")
	fmt.Println("  hosts    Manage virtual hosts")
	fmt.Println("  generate Generate nginx configuration")
	fmt.Println("  help     Show this help message")
	fmt.Println("\nServer options:")
	fmt.Println("  -port <port>       Server port (overrides config)")
	fmt.Println("  -public <dir>      Public directory (overrides config)")
	fmt.Println("\nNginx options:")
	fmt.Println("  -sync    Sync virtual hosts from database to nginx")
	fmt.Println("  -reload  Reload nginx configuration")
	fmt.Println("  -test    Test nginx configuration")
	fmt.Println("  -status  Show nginx status")
	fmt.Println("  -list    List nginx virtual hosts")
	fmt.Println("\nHosts options:")
	fmt.Println("  -list              List all virtual hosts")
	fmt.Println("  -add               Add a new virtual host")
	fmt.Println("  -remove            Remove a virtual host")
	fmt.Println("  -enable            Enable a virtual host")
	fmt.Println("  -disable           Disable a virtual host")
	fmt.Println("  -domain <domain>   Domain name")
	fmt.Println("  -public <dir>      Public directory")
	fmt.Println("  -port <port>       Port (default: 80)")
	fmt.Println("  -ssl               Enable SSL")
	fmt.Println("  -cert <path>       SSL certificate path")
	fmt.Println("  -key <path>        SSL key path")
	fmt.Println("\nGenerate options:")
	fmt.Println("  -domain <domain>   Domain name for nginx config")
	fmt.Println("  -output <file>     Output file (default: stdout)")
	fmt.Println("\nExamples:")
	fmt.Println("  gubinnet server")
	fmt.Println("  gubinnet server -port 3000")
	fmt.Println("  gubinnet nginx -sync")
	fmt.Println("  gubinnet hosts -list")
	fmt.Println("  gubinnet hosts -add -domain example.com -public /var/www/example")
	fmt.Println("  gubinnet hosts -enable -domain example.com")
	fmt.Println("  gubinnet generate -domain example.com -output /etc/nginx/sites-available/example.com")
}

func runServer(port, publicDir string) {
	// Load configuration from gubinnet.conf
	config, err := LoadConfig("gubinnet.conf")
	if err != nil {
		log.Printf("Error loading config from gubinnet.conf: %v, using defaults", err)
		config = DefaultConfig()
	}

	// Override config with CLI flags
	if port != "" {
		config.Port = port
	}
	if publicDir != "" {
		config.PublicDir = publicDir
	}

	// Create new GubinNET server instance
	server := NewGubinNET(config)

	// Setup API routes for virtual host management
	if server.VirtualHostManager != nil {
		server.SetupAPIRoutes()
	}

	// Start the server
	server.Start()
}

func runNginxCommand(sync, reload, test, status, list bool) {
	nginxHandler := NewNginxHandler()

	switch {
	case sync:
		// Load config and connect to database
		config, err := LoadConfig("gubinnet.conf")
		if err != nil {
			log.Fatalf("Error loading config: %v", err)
		}

		if config.Database.Host == "" {
			log.Fatal("Database configuration not found")
		}

		db, err := config.ConnectDB()
		if err != nil {
			log.Fatalf("Failed to connect to database: %v", err)
		}
		defer db.Close()

		vhm := NewVirtualHostManager(db)
		if err := nginxHandler.SyncFromDatabase(vhm); err != nil {
			log.Fatalf("Failed to sync: %v", err)
		}
		fmt.Println("Virtual hosts synced to nginx successfully")

	case reload:
		if err := nginxHandler.ReloadNginx(); err != nil {
			log.Fatalf("Failed to reload nginx: %v", err)
		}
		fmt.Println("Nginx reloaded successfully")

	case test:
		output, err := nginxHandler.TestConfig()
		fmt.Println(output)
		if err != nil {
			log.Fatal("Nginx configuration test failed")
		}
		fmt.Println("Nginx configuration test passed")

	case status:
		output, err := nginxHandler.GetNginxStatus()
		fmt.Println(output)
		if err != nil {
			log.Printf("Warning: %v", err)
		}

	case list:
		hosts, err := nginxHandler.ListVirtualHosts()
		if err != nil {
			log.Fatalf("Failed to list hosts: %v", err)
		}
		fmt.Println("Nginx virtual hosts:")
		for _, host := range hosts {
			fmt.Printf("  - %s\n", host)
		}

	default:
		fmt.Println("Please specify an nginx action: -sync, -reload, -test, -status, or -list")
	}
}

func runHostsCommand(list, add, remove, enable, disable bool, domain, publicDir, port string, ssl bool, cert, key string) {
	// Load config and connect to database
	config, err := LoadConfig("gubinnet.conf")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	if config.Database.Host == "" {
		log.Fatal("Database configuration not found. Cannot manage virtual hosts without database.")
	}

	db, err := config.ConnectDB()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	vhm := NewVirtualHostManager(db)

	switch {
	case list:
		hosts, err := vhm.GetAllVirtualHostsIncludingDisabled()
		if err != nil {
			log.Fatalf("Failed to list hosts: %v", err)
		}
		fmt.Println("Virtual hosts:")
		fmt.Println("ID\tDomain\t\t\tPublic Dir\t\t\tPort\tEnabled\tSSL")
		fmt.Println("--------------------------------------------------------------------------------")
		for _, h := range hosts {
			enabled := "yes"
			if !h.Enabled {
				enabled = "no"
			}
			sslStatus := "no"
			if h.SSLRequired {
				sslStatus = "yes"
			}
			fmt.Printf("%d\t%-20s\t%-25s\t%s\t%s\t\t%s\n", h.ID, h.Domain, h.PublicDir, h.Port, enabled, sslStatus)
		}

	case add:
		if domain == "" || publicDir == "" {
			log.Fatal("Domain and public directory are required for adding a host")
		}
		vh := &VirtualHost{
			Domain:      domain,
			PublicDir:   publicDir,
			Port:        port,
			Enabled:     true,
			SSLRequired: ssl,
			SSLCert:     cert,
			SSLKey:      key,
		}
		if err := vhm.CreateVirtualHost(vh); err != nil {
			log.Fatalf("Failed to create host: %v", err)
		}
		fmt.Printf("Created virtual host: %s\n", domain)

	case remove:
		if domain == "" {
			log.Fatal("Domain is required for removing a host")
		}
		if err := vhm.DeleteVirtualHostByDomain(domain); err != nil {
			log.Fatalf("Failed to remove host: %v", err)
		}
		fmt.Printf("Removed virtual host: %s\n", domain)

	case enable:
		if domain == "" {
			log.Fatal("Domain is required for enabling a host")
		}
		if err := vhm.EnableVirtualHost(domain); err != nil {
			log.Fatalf("Failed to enable host: %v", err)
		}
		fmt.Printf("Enabled virtual host: %s\n", domain)

	case disable:
		if domain == "" {
			log.Fatal("Domain is required for disabling a host")
		}
		if err := vhm.DisableVirtualHost(domain); err != nil {
			log.Fatalf("Failed to disable host: %v", err)
		}
		fmt.Printf("Disabled virtual host: %s\n", domain)

	default:
		fmt.Println("Please specify a hosts action: -list, -add, -remove, -enable, or -disable")
	}
}

func runGenerateCommand(domain, output string) {
	if domain == "" {
		log.Fatal("Domain is required for generating nginx config")
	}

	// Load config and connect to database
	config, err := LoadConfig("gubinnet.conf")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	nginxHandler := NewNginxHandler()

	// Try to get from database first
	if config.Database.Host != "" {
		db, err := config.ConnectDB()
		if err == nil {
			defer db.Close()
			vhm := NewVirtualHostManager(db)
			vh, err := vhm.GetVirtualHostByDomain(domain)
			if err == nil {
				nginxConfig := nginxHandler.GenerateVirtualHostConfig(vh)
				writeConfigOutput(nginxConfig, output)
				return
			}
		}
	}

	// Generate a basic config if not in database
	vh := &VirtualHost{
		Domain:    domain,
		PublicDir: "/var/www/" + domain,
		Port:      "80",
		Enabled:   true,
	}
	nginxConfig := nginxHandler.GenerateVirtualHostConfig(vh)
	writeConfigOutput(nginxConfig, output)
}

func writeConfigOutput(config, output string) {
	if output != "" {
		if err := os.WriteFile(output, []byte(config), 0644); err != nil {
			log.Fatalf("Failed to write output file: %v", err)
		}
		fmt.Printf("Configuration written to: %s\n", output)
	} else {
		fmt.Println(config)
	}
}
