package metrics

import (
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Метрики
var (
	// HTTP метрики
	RequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of HTTP requests",
	}, []string{"method", "path", "status"})

	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "HTTP request duration in seconds",
		Buckets: []float64{0.1, 0.5, 1, 2.5, 5, 10},
	}, []string{"method", "path"})

	ActiveConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "http_active_connections",
		Help: "Number of active HTTP connections",
	})

	RequestSize = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_size_bytes",
		Help:    "HTTP request size in bytes",
		Buckets: prometheus.ExponentialBuckets(100, 10, 8),
	}, []string{"method", "path"})

	ResponseSize = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_response_size_bytes",
		Help:    "HTTP response size in bytes",
		Buckets: prometheus.ExponentialBuckets(100, 10, 8),
	}, []string{"method", "path"})

	// Метрики модулей
	ModuleExecutions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "module_executions_total",
		Help: "Total number of module executions",
	}, []string{"language", "name", "status"})

	ModuleDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "module_execution_duration_seconds",
		Help:    "Module execution duration in seconds",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
	}, []string{"language", "name"})

	ModuleErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "module_errors_total",
		Help: "Total number of module errors",
	}, []string{"language", "name", "error_type"})

	// Кэш метрики
	CacheHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "cache_hits_total",
		Help: "Total number of cache hits",
	}, []string{"type"})

	CacheMisses = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "cache_misses_total",
		Help: "Total number of cache misses",
	}, []string{"type"})

	CacheSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cache_size_bytes",
		Help: "Current cache size in bytes",
	}, []string{"type"})

	// Системные метрики
	GoroutinesCount = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "goroutines_total",
		Help: "Current number of goroutines",
	})

	MemoryUsage = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "memory_usage_bytes",
		Help: "Memory usage in bytes",
	}, []string{"type"})
)

// MetricsCollector сборщик метрик
type MetricsCollector struct {
	registry *prometheus.Registry
}

// NewMetricsCollector создает новый сборщик метрик
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		registry: prometheus.NewRegistry(),
	}
}

// Handler возвращает HTTP handler для метрик Prometheus
func (m *MetricsCollector) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// StartSystemMetrics начинает сбор системных метрик
func (m *MetricsCollector) StartSystemMetrics() {
	go func() {
		for range time.Tick(30 * time.Second) {
			// Сбор метрик goroutines
			GoroutinesCount.Set(float64(runtime.NumGoroutine()))

			// Сбор метрик памяти
			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)

			MemoryUsage.WithLabelValues("heap").Set(float64(memStats.HeapAlloc))
			MemoryUsage.WithLabelValues("stack").Set(float64(memStats.StackInuse))
			MemoryUsage.WithLabelValues("system").Set(float64(memStats.Sys))
		}
	}()
}

// RecordHTTPRequest записывает метрики HTTP запроса
func RecordHTTPRequest(method, path string, status int, duration time.Duration, requestSize, responseSize int64) {
	statusStr := strconv.Itoa(status)

	RequestsTotal.WithLabelValues(method, path, statusStr).Inc()
	RequestDuration.WithLabelValues(method, path).Observe(duration.Seconds())

	if requestSize > 0 {
		RequestSize.WithLabelValues(method, path).Observe(float64(requestSize))
	}

	if responseSize > 0 {
		ResponseSize.WithLabelValues(method, path).Observe(float64(responseSize))
	}
}

// RecordModuleExecution записывает метрики выполнения модуля
func RecordModuleExecution(language, name string, success bool, duration time.Duration, err error) {
	status := "success"
	if !success {
		status = "error"
	}

	ModuleExecutions.WithLabelValues(language, name, status).Inc()
	ModuleDuration.WithLabelValues(language, name).Observe(duration.Seconds())

	if err != nil {
		errorType := "unknown"
		switch err.(type) {
		case *os.PathError:
			errorType = "file_system"
		case *exec.ExitError:
			errorType = "execution"
		default:
			errorType = "runtime"
		}
		ModuleErrors.WithLabelValues(language, name, errorType).Inc()
	}
}

// RecordCacheAccess записывает метрики доступа к кэшу
func RecordCacheAccess(cacheType string, hit bool) {
	if hit {
		CacheHits.WithLabelValues(cacheType).Inc()
	} else {
		CacheMisses.WithLabelValues(cacheType).Inc()
	}
}

// UpdateCacheSize обновляет метрики размера кэша
func UpdateCacheSize(cacheType string, size int64) {
	CacheSize.WithLabelValues(cacheType).Set(float64(size))
}

// HTTPMiddleware middleware для сбора HTTP метрик
func HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Обертываем ResponseWriter для получения размера ответа
		wrapped := &responseWriterWrapper{w: w, status: 200}

		// Получаем размер запроса
		var requestSize int64
		if r.ContentLength > 0 {
			requestSize = r.ContentLength
		}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		RecordHTTPRequest(r.Method, r.URL.Path, wrapped.status, duration, requestSize, int64(wrapped.size))
	})
}

// responseWriterWrapper для захвата статуса и размера ответа
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
