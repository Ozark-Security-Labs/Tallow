package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Ozark-Security-Labs/Tallow/internal/config"
	"github.com/Ozark-Security-Labs/Tallow/internal/metrics"
	"github.com/Ozark-Security-Labs/Tallow/internal/requestid"
	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
	"github.com/go-chi/chi/v5"
	"log/slog"
	"net/http"
	"time"
)

type Check func(context.Context) error
type Server struct {
	Config       config.Config
	Logger       *slog.Logger
	Checks       map[string]Check
	Metrics      *metrics.Metrics
	Findings     FindingReader
	Graph        GraphReader
	Correlations CorrelationReader
	Handler      http.Handler
}

func New(cfg config.Config, logger *slog.Logger, checks map[string]Check) *Server {
	return NewWithFindings(cfg, logger, checks, EmptyFindingStore{})
}

func NewWithFindings(
	cfg config.Config,
	logger *slog.Logger,
	checks map[string]Check,
	findings FindingReader,
) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{Config: cfg, Logger: logger, Checks: checks, Metrics: metrics.New(), Findings: findings, Graph: EmptyGraphStore{}, Correlations: EmptyCorrelationStore{}}
	s.Handler = s.routes()
	return s
}
func (s *Server) routes() http.Handler {
	r := chi.NewRouter()
	r.Use(requestid.Middleware)
	r.Use(s.recoverer)
	r.Use(s.logger)
	if s.Config.Metrics.Enabled {
		r.Use(s.Metrics.Middleware)
	}
	r.Get("/healthz", s.health)
	r.Get("/readyz", s.ready)
	r.Get("/v1/findings", s.listFindings)
	r.Get("/v1/findings/{id}", s.getFinding)
	r.Get("/v1/graph/affected-direct-dependencies", s.listAffectedDirectDependencies)
	r.Get("/v1/source-correlations", s.listCorrelations)
	r.Get("/v1/package-versions/{id}/statuses", s.listAffectedDirectDependencies)
	r.Get("/v1/package-versions/{id}/transitive-impacts", s.listAffectedDirectDependencies)
	r.Get("/v1/statuses/{id}/affected-dependents", s.listAffectedDirectDependencies)
	if s.Config.Metrics.Enabled {
		r.Handle("/metrics", s.Metrics.Handler())
	}
	return r
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	for name, check := range s.Checks {
		if err := check(r.Context()); err != nil {
			s.Metrics.Readiness.WithLabelValues(name, "failed").Inc()
			var terr *tallowerr.Error
			if !errors.As(err, &terr) {
				err = tallowerr.Wrap(tallowerr.CodeDatabaseUnavailable, "readiness check failed", err)
			}
			writeError(w, r, err)
			return
		}
		s.Metrics.Readiness.WithLabelValues(name, "ok").Inc()
	}
	writeJSON(w, 200, map[string]string{"status": "ready"})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	id, _ := requestid.FromContext(r.Context())
	var code = tallowerr.CodeInternal
	if e, ok := err.(*tallowerr.Error); ok {
		code = e.Code
	}
	if rr, ok := w.(*responseRecorder); ok {
		rr.errorCode = string(code)
	}
	writeJSON(w, tallowerr.HTTPStatus(code), tallowerr.JSONEnvelope(err, id))
}
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recover() != nil {
				writeError(w, r, tallowerr.New(tallowerr.CodeInternal, "internal error"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type responseRecorder struct {
	http.ResponseWriter
	status    int
	errorCode string
}

func (rr *responseRecorder) WriteHeader(status int) {
	rr.status = status
	rr.ResponseWriter.WriteHeader(status)
}

func (s *Server) logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rr := &responseRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rr, r)
		id, _ := requestid.FromContext(r.Context())
		s.Logger.Info("http_request", "request_id", id, "method", r.Method, "route", metrics.RouteLabel(r), "status", rr.status, "error_code", rr.errorCode, "latency", time.Since(start).String())
	})
}
