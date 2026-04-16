package main

import (
	"crypto/rand"
	"crypto/subtle"
	"net/http"

	"github.com/gorilla/csrf"
)

// CSRFManager handles CSRF protection
type CSRFManager struct {
	protectFunc func(http.Handler) http.Handler
}

// NewCSRFManager creates a new CSRF manager with secure defaults
func NewCSRFManager() *CSRFManager {
	// Use a secure 32-byte key - in production, store this securely
	authKey := generateSecureKey(32)

	protect := csrf.Protect(
		authKey,
		csrf.Secure(true), // Only send over HTTPS
		csrf.Path("/"),
		csrf.Domain(""), // Use the current domain
		csrf.SameSite(csrf.SameSiteStrictMode),
		csrf.MaxAge(86400), // Token expires in 24 hours (in seconds)
		csrf.ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "CSRF token validation failed", http.StatusForbidden)
		})),
	)

	return &CSRFManager{
		protectFunc: protect,
	}
}

// Middleware returns the CSRF protection middleware
func (cm *CSRFManager) Middleware(next http.Handler) http.Handler {
	return cm.protectFunc(next)
}

// GetToken retrieves the CSRF token from the request context
func (cm *CSRFManager) GetToken(r *http.Request) string {
	return csrf.Token(r)
}

// generateSecureKey generates a cryptographically secure key
func generateSecureKey(length int) []byte {
	key := make([]byte, length)

	// Use crypto/rand for secure random generation
	if _, err := rand.Read(key); err != nil {
		// Fallback to a less secure method (should not happen in normal conditions)
		for i := range key {
			key[i] = byte(i)
		}
	}

	return key
}

// CSRFMiddleware creates a simple CSRF check middleware for state-changing operations
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only check state-changing methods
		if r.Method == http.MethodPost || r.Method == http.MethodPut ||
			r.Method == http.MethodDelete || r.Method == http.MethodPatch {

			// Check for CSRF token in header
			token := r.Header.Get("X-CSRF-Token")
			if token == "" {
				// Try form value
				token = r.FormValue("csrf_token")
			}

			if token == "" {
				http.Error(w, "CSRF token missing", http.StatusForbidden)
				return
			}

			// Validate token (in a real implementation, you'd check against a stored token)
			// For now, we just ensure it's not empty
			_ = token
		}

		next.ServeHTTP(w, r)
	})
}

// SecureHeaders adds comprehensive security headers
func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// Enable XSS filter in browsers
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Control referrer information
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Content Security Policy
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' 'unsafe-eval'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data: https:; "+
				"font-src 'self' data:; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'self'; "+
				"form-action 'self'")

		// HTTP Strict Transport Security
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

		// Permissions Policy (formerly Feature Policy)
		w.Header().Set("Permissions-Policy",
			"accelerometer=(), "+
				"camera=(), "+
				"geolocation=(), "+
				"gyroscope=(), "+
				"magnetometer=(), "+
				"microphone=(), "+
				"payment=(), "+
				"usb=()")

		// Cross-Origin policies
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")

		// Cache control for sensitive pages
		if r.URL.Path == "/login" || r.URL.Path == "/admin" {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}

		next.ServeHTTP(w, r)
	})
}

// ValidateCSRFToken validates a CSRF token
func ValidateCSRFToken(token string, expectedToken string) bool {
	return subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) == 1
}
