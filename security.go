package main

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SecurityManager handles all security-related functionality
type SecurityManager struct {
	config        Config
	requestCounts map[string]*RequestCounter
	mu            sync.RWMutex
	blockedIPs    map[string]time.Time
}

// RequestCounter keeps track of requests from an IP
type RequestCounter struct {
	count    int
	firstReq time.Time
}

// NewSecurityManager creates a new security manager
func NewSecurityManager(config Config) *SecurityManager {
	sm := &SecurityManager{
		config:        config,
		requestCounts: make(map[string]*RequestCounter),
		blockedIPs:    make(map[string]time.Time),
	}
	
	// Start cleanup goroutine to remove old entries
	go sm.cleanupOldEntries()
	
	return sm
}

// cleanupOldEntries removes old request counts and expired blocks
func (sm *SecurityManager) cleanupOldEntries() {
	for {
		time.Sleep(5 * time.Minute)
		sm.mu.Lock()
		
		// Remove old request counts
		now := time.Now()
		for ip, counter := range sm.requestCounts {
			if now.Sub(counter.firstReq).Seconds() > float64(sm.config.AntiDDoS.WindowSeconds) {
				delete(sm.requestCounts, ip)
			}
		}
		
		// Remove expired blocks
		for ip, blockTime := range sm.blockedIPs {
			if now.Sub(blockTime).Minutes() > float64(sm.config.AntiDDoS.BlockDuration) {
				delete(sm.blockedIPs, ip)
			}
		}
		
		sm.mu.Unlock()
	}
}

// IsBlocked checks if an IP is blocked
func (sm *SecurityManager) IsBlocked(r *http.Request) bool {
	ip := getRealIP(r)
	
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	// Check if IP is explicitly blocked
	for _, blockedIP := range sm.config.BlockedIPs {
		if ip == blockedIP {
			return true
		}
	}
	
	// Check if IP is in temporary block list
	if blockTime, exists := sm.blockedIPs[ip]; exists {
		if time.Since(blockTime).Minutes() < float64(sm.config.AntiDDoS.BlockDuration) {
			return true
		} else {
			// Block has expired, remove it
			delete(sm.blockedIPs, ip)
		}
	}
	
	// Check if only specific IPs are allowed
	if len(sm.config.AllowedIPs) > 0 {
		allowed := false
		for _, allowedIP := range sm.config.AllowedIPs {
			if ip == allowedIP {
				allowed = true
				break
			}
		}
		if !allowed {
			return true
		}
	}
	
	return false
}

// CheckAndIncrementRequestCount checks if request count exceeds limit and increments it
func (sm *SecurityManager) CheckAndIncrementRequestCount(r *http.Request) bool {
	if !sm.config.AntiDDoS.Enabled {
		return true
	}
	
	ip := getRealIP(r)
	now := time.Now()
	
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	counter, exists := sm.requestCounts[ip]
	if !exists {
		sm.requestCounts[ip] = &RequestCounter{
			count:    1,
			firstReq: now,
		}
		return true
	}
	
	// Check if window has passed
	if now.Sub(counter.firstReq).Seconds() > float64(sm.config.AntiDDoS.WindowSeconds) {
		// Reset counter for new window
		sm.requestCounts[ip] = &RequestCounter{
			count:    1,
			firstReq: now,
		}
		return true
	}
	
	// Increment count and check limit
	counter.count++
	if counter.count > sm.config.AntiDDoS.MaxRequests {
		// Block the IP
		sm.blockedIPs[ip] = now
		return false
	}
	
	return true
}

// IsBot checks if the request is from a bot
func (sm *SecurityManager) IsBot(r *http.Request) bool {
	userAgent := strings.ToLower(r.Header.Get("User-Agent"))
	if userAgent == "" {
		return true // No user agent is suspicious
	}
	
	// Check against allowed bots
	for _, allowedBot := range sm.config.AllowedBots {
		if strings.Contains(userAgent, strings.ToLower(allowedBot)) {
			return false // This is an allowed bot
		}
	}
	
	// Check for bot indicators
	botIndicators := []string{
		"bot", "crawl", "spider", "slurp", "teoma", 
		"heritrix", "gigabot", "robot", "yeti", "ia_archiver",
		"screaming frog", "chrome-lighthouse", "google page speed",
	}
	
	for _, indicator := range botIndicators {
		if strings.Contains(userAgent, indicator) {
			return true
		}
	}
	
	// Additional checks: requests without common browser headers
	if r.Header.Get("Accept-Language") == "" && r.Header.Get("Accept-Encoding") == "" {
		return true
	}
	
	return false
}

// SanitizeInput sanitizes user input to prevent XSS and other attacks
func (sm *SecurityManager) SanitizeInput(input string) string {
	// Remove potentially dangerous characters/patterns
	reScripts := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	input = reScripts.ReplaceAllString(input, "")
	
	reOnEvents := regexp.MustCompile(`(?i)on\w+\s*=`)
	input = reOnEvents.ReplaceAllString(input, "")
	
	reJavascript := regexp.MustCompile(`(?i)javascript:`)
	input = reJavascript.ReplaceAllString(input, "")
	
	reVbscript := regexp.MustCompile(`(?i)vbscript:`)
	input = reVbscript.ReplaceAllString(input, "")
	
	reDataURI := regexp.MustCompile(`(?i)data:`)
	input = reDataURI.ReplaceAllString(input, "")
	
	return input
}

// ValidatePath validates file paths to prevent directory traversal
func (sm *SecurityManager) ValidatePath(path string) bool {
	// Check for directory traversal attempts
	if strings.Contains(path, "../") || strings.Contains(path, "..\\") {
		return false
	}
	
	// Additional validation could go here
	
	return true
}

// SecurityHeaders adds security headers to the response
func (sm *SecurityManager) SecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
}

// getRealIP extracts the real IP address from the request, considering proxies
func getRealIP(r *http.Request) string {
	// Check X-Forwarded-For header
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	
	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		if net.ParseIP(realIP) != nil {
			return realIP
		}
	}
	
	// Fall back to remote address
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	
	return r.RemoteAddr
}

// Middleware returns a middleware function that applies all security checks
func (sm *SecurityManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add security headers
		sm.SecurityHeaders(w)
		
		// Check if IP is blocked
		if sm.IsBlocked(r) {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		
		// Check for DDoS
		if !sm.CheckAndIncrementRequestCount(r) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		
		// Check for bots (if protection is enabled)
		if sm.config.AntiDDoS.ChallengeEnabled && sm.IsBot(r) {
			// For bots, we can return a JavaScript challenge or simply block
			// For now, we'll block non-allowed bots
			if !sm.IsAllowedBot(r) {
				http.Error(w, "Bot access denied", http.StatusForbidden)
				return
			}
		}
		
		// Sanitize important headers and parameters
		for key, values := range r.Header {
			for i, value := range values {
				r.Header[key][i] = sm.SanitizeInput(value)
			}
		}
		
		next.ServeHTTP(w, r)
	})
}

// IsAllowedBot checks if the request is from an allowed bot
func (sm *SecurityManager) IsAllowedBot(r *http.Request) bool {
	userAgent := strings.ToLower(r.Header.Get("User-Agent"))
	
	for _, allowedBot := range sm.config.AllowedBots {
		if strings.Contains(userAgent, strings.ToLower(allowedBot)) {
			return true
		}
	}
	
	return false
}

// BlockIP temporarily blocks an IP address
func (sm *SecurityManager) BlockIP(ip string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	sm.blockedIPs[ip] = time.Now()
}

// LogSecurityEvent logs security-related events
func (sm *SecurityManager) LogSecurityEvent(eventType, message string, r *http.Request) {
	ip := getRealIP(r)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	
	logMsg := fmt.Sprintf("[%s] SECURITY %s: %s - IP: %s, Path: %s, UA: %s", 
		timestamp, eventType, message, ip, r.URL.Path, r.UserAgent())
	
	fmt.Println(logMsg)
	// In a real implementation, you'd write this to a log file
}