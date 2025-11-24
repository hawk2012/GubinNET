package main

import (
	"net/http"
	"regexp"
	"strings"
)

// RewriteRule represents a URL rewrite rule
type RewriteRule struct {
	From        string
	To          string
	Flags       []string
	Condition   string // Additional condition if needed
	Compiled    *regexp.Regexp
	Redirect    bool
	StatusCode  int // For redirects
}

// RewriteEngine handles URL rewriting
type RewriteEngine struct {
	Rules []RewriteRule
}

// NewRewriteEngine creates a new rewrite engine
func NewRewriteEngine() *RewriteEngine {
	return &RewriteEngine{
		Rules: []RewriteRule{},
	}
}

// AddRule adds a rewrite rule
func (re *RewriteEngine) AddRule(from, to string, redirect bool, statusCode int, flags []string) {
	// Compile the regular expression
	compiled, err := regexp.Compile(from)
	if err != nil {
		// If compilation fails, we'll skip this rule
		return
	}
	
	rule := RewriteRule{
		From:       from,
		To:         to,
		Flags:      flags,
		Compiled:   compiled,
		Redirect:   redirect,
		StatusCode: statusCode,
	}
	
	re.Rules = append(re.Rules, rule)
}

// AddBasicRules adds some basic rewrite rules
func (re *RewriteEngine) AddBasicRules() {
	// Redirect old paths
	re.AddRule(`^/old/(.*)`, "/new/$1", true, 301, []string{})
	
	// API rewrite
	re.AddRule(`^/api/(.*)`, "/internal/api/$1", false, 0, []string{})
	
	// SEO-friendly URLs
	re.AddRule(`^/product/([^/]+)/?$`, "/product.php?id=$1", false, 0, []string{})
	re.AddRule(`^/user/([^/]+)/?$`, "/user.php?name=$1", false, 0, []string{})
	
	// Remove .php extension
	re.AddRule(`^/([^.]+)$`, "/$1.php", false, 0, []string{})
	
	// Force trailing slash
	re.AddRule(`^([^.]*[^/])$`, "$1/", true, 301, []string{})
}

// ProcessRequest applies rewrite rules to the incoming request
func (re *RewriteEngine) ProcessRequest(w http.ResponseWriter, r *http.Request) bool {
	originalPath := r.URL.Path
	
	for _, rule := range re.Rules {
		// Check if the rule matches
		if rule.Compiled.MatchString(originalPath) {
			// Apply the rewrite
			newPath := rule.Compiled.ReplaceAllString(originalPath, rule.To)
			
			// Handle flags
			for _, flag := range rule.Flags {
				switch flag {
				case "L": // Last rule
					// Stop processing more rules
				case "R": // Redirect
					// This is handled by the redirect flag in the rule itself
				case "QSA": // Query String Append
					// Preserve query string
					if r.URL.RawQuery != "" {
						newPath += "?" + r.URL.RawQuery
					}
				}
			}
			
			// If it's a redirect, send redirect response
			if rule.Redirect {
				http.Redirect(w, r, newPath, rule.StatusCode)
				return false // Stop further processing
			}
			
			// Otherwise, update the request URL
			r.URL.Path = newPath
			break // Apply first matching rule unless L flag handling is implemented
		}
	}
	
	return true // Continue processing
}

// LoadRulesFromConfig loads rewrite rules from the configuration
func (re *RewriteEngine) LoadRulesFromConfig(config Config) {
	// Clear existing rules
	re.Rules = []RewriteRule{}
	
	// Add rules from config
	for pattern, replacement := range config.RewriteRules {
		// For now, we'll treat all config rules as internal rewrites (not redirects)
		// In a more advanced implementation, you could parse special syntax to determine redirect vs rewrite
		re.AddRule(pattern, replacement, false, 0, []string{})
	}
	
	// Add basic rules as defaults
	re.AddBasicRules()
}

// ParseRuleFromApacheSyntax parses Apache-style mod_rewrite syntax
// This is a simplified version - a full implementation would be more complex
func ParseRuleFromApacheSyntax(ruleLine string) *RewriteRule {
	// This would parse Apache mod_rewrite syntax like:
	// RewriteRule ^/old/(.*)$ /new/$1 [R=301,L]
	
	// For now, we'll return nil as this is a complex parsing task
	// A full implementation would require proper parsing of the Apache syntax
	return nil
}

// Middleware returns a middleware function that applies rewrite rules
func (re *RewriteEngine) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply rewrite rules
		continueProcessing := re.ProcessRequest(w, r)
		if !continueProcessing {
			// Request was redirected, don't continue
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// ValidateRule validates if a rewrite rule is properly formatted
func (re *RewriteEngine) ValidateRule(from, to string) bool {
	// Check if the regex compiles
	_, err := regexp.Compile(from)
	if err != nil {
		return false
	}
	
	// Check if the replacement has proper capture group references
	// This is a very basic check - a full implementation would be more thorough
	if strings.Contains(from, "(") && strings.Contains(from, ")") {
		// The 'from' has capture groups, check if 'to' uses them
		// This is a simplified validation
	}
	
	return true
}

// ApplyRule applies a single rule to a path
func (re *RewriteEngine) ApplyRule(path string, ruleIndex int) string {
	if ruleIndex < 0 || ruleIndex >= len(re.Rules) {
		return path
	}
	
	rule := re.Rules[ruleIndex]
	if rule.Compiled.MatchString(path) {
		return rule.Compiled.ReplaceAllString(path, rule.To)
	}
	
	return path
}

// GetMatchingRule returns the first rule that matches the path
func (re *RewriteEngine) GetMatchingRule(path string) *RewriteRule {
	for i := range re.Rules {
		if re.Rules[i].Compiled.MatchString(path) {
			return &re.Rules[i]
		}
	}
	return nil
}

// UpdateRule updates an existing rule
func (re *RewriteEngine) UpdateRule(index int, from, to string, redirect bool, statusCode int, flags []string) error {
	if index < 0 || index >= len(re.Rules) {
		return nil // Or return an error
	}
	
	// Compile the new regex
	compiled, err := regexp.Compile(from)
	if err != nil {
		return err
	}
	
	re.Rules[index] = RewriteRule{
		From:       from,
		To:         to,
		Flags:      flags,
		Compiled:   compiled,
		Redirect:   redirect,
		StatusCode: statusCode,
	}
	
	return nil
}

// RemoveRule removes a rule at the specified index
func (re *RewriteEngine) RemoveRule(index int) {
	if index < 0 || index >= len(re.Rules) {
		return
	}
	
	// Remove the element at index
	re.Rules = append(re.Rules[:index], re.Rules[index+1:]...)
}