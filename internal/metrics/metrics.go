package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"strconv"
	"time"
)

type Metrics struct {
	Registry  *prometheus.Registry
	Requests  *prometheus.CounterVec
	Duration  *prometheus.HistogramVec
	Readiness *prometheus.CounterVec
}

func New() *Metrics {
	r := prometheus.NewRegistry()
	m := &Metrics{Registry: r, Requests: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tallow_http_requests_total", Help: "HTTP requests."}, []string{"method", "path", "status"}), Duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "tallow_http_request_duration_seconds", Help: "HTTP request duration."}, []string{"method", "path", "status"}), Readiness: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tallow_readiness_check_total", Help: "Readiness checks."}, []string{"check", "status"})}
	r.MustRegister(m.Requests, m.Duration, m.Readiness)
	return m
}
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}

type rec struct {
	http.ResponseWriter
	status int
}

func (r *rec) WriteHeader(s int) { r.status = s; r.ResponseWriter.WriteHeader(s) }
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rr := &rec{ResponseWriter: w, status: 200}
		start := time.Now()
		next.ServeHTTP(rr, r)
		path := r.URL.Path
		status := strconv.Itoa(rr.status)
		m.Requests.WithLabelValues(r.Method, path, status).Inc()
		m.Duration.WithLabelValues(r.Method, path, status).Observe(time.Since(start).Seconds())
	})
}
