package server

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// responseWriterWrapper для захвата статус-кода
type responseWriterWrapper struct {
	w      http.ResponseWriter
	status int
	size   int
}

func (w *responseWriterWrapper) Header() http.Header {
	return w.w.Header()
}

func (w *responseWriterWrapper) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	size, err := w.w.Write(b)
	w.size += size
	return size, err
}

func (w *responseWriterWrapper) WriteHeader(statusCode int) {
	w.status = statusCode
	w.w.WriteHeader(statusCode)
}

func (s *GubinServer) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.ToLower(r.URL.Path)

		// Защита от path traversal и других атак
		re := regexp.MustCompile(`(\.\./|%2e%2e|\.env|phpmyadmin|shell|setup-config\.php|device\.rsp)`)
		if re.MatchString(path) {
			ip := s.getRealIP(r)
			requestID := w.Header().Get("X-Request-ID")

			s.logger.Warning("Blocked suspicious request", map[string]interface{}{
				"path":       path,
				"ip":         ip,
				"request_id": requestID,
			})

			s.serveErrorPage(w, r, http.StatusForbidden, "Access Denied", "", requestID)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *GubinServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := uuid.New().String()

		wrapped := &responseWriterWrapper{w: w}
		wrapped.Header().Set("X-Request-ID", requestID)

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start).Seconds()
		statusCode := wrapped.status
		if statusCode == 0 {
			statusCode = http.StatusOK
		}

		// Метрики
		requestsTotal.WithLabelValues(r.Method, r.URL.Path, strconv.Itoa(statusCode)).Inc()
		requestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)

		// Логирование
		s.logger.Info("Request processed", map[string]interface{}{
			"method":     r.Method,
			"path":       r.URL.Path,
			"status":     statusCode,
			"duration":   duration,
			"remote":     r.RemoteAddr,
			"user_agent": r.UserAgent(),
			"request_id": requestID,
			"bytes_sent": wrapped.size,
		})
	})
}

func (s *GubinServer) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		activeConnections.Inc()
		defer activeConnections.Dec()
		next.ServeHTTP(w, r)
	})
}

func (s *GubinServer) getRealIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}
