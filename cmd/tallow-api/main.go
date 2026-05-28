package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/api"
	"github.com/Ozark-Security-Labs/Tallow/internal/auth"
	"github.com/Ozark-Security-Labs/Tallow/internal/auth/local"
	"github.com/Ozark-Security-Labs/Tallow/internal/config"
	"github.com/Ozark-Security-Labs/Tallow/internal/db/sqlc"
	"github.com/Ozark-Security-Labs/Tallow/internal/events"
	"github.com/Ozark-Security-Labs/Tallow/internal/findings"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	cfg, err := config.LoadFromEnvironment()
	if err != nil {
		log.Fatal(err)
	}
	pool, err := pgxpool.New(context.Background(), cfg.Postgres.DSN)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	checks := map[string]api.Check{
		"postgres": func(ctx context.Context) error {
			cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			return pool.Ping(cctx)
		},
		"nats_jetstream": func(ctx context.Context) error {
			bus, err := events.Connect(ctx, cfg.NATS.URL)
			if err != nil {
				return err
			}
			defer bus.Conn.Close()
			return bus.Ready(ctx)
		},
	}
	srv := api.NewWithFindings(
		cfg,
		slog.Default(),
		checks,
		findings.NewSQLStore(sqlc.New(pool)),
	)
	providers := []auth.Provider{}
	if cfg.Auth.Local.Enabled {
		providers = append(providers, local.NewProvider(local.Config{Enabled: true, BootstrapAdminEmail: cfg.Auth.Local.BootstrapAdminEmail, BootstrapAdminPassword: cfg.Auth.Local.BootstrapAdminPassword}, nil))
	}
	authManager, err := auth.NewManager(providers...)
	if err != nil {
		log.Fatal(err)
	}
	srv.Auth = authManager
	ttl, err := time.ParseDuration(cfg.Auth.Session.TTL)
	if err != nil {
		log.Fatal(err)
	}
	srv.SessionManager = auth.NewSessionManager(auth.NewMemorySessionStore(), auth.SessionOptions{CookieName: cfg.Auth.Session.CookieName, TTL: ttl, SecureCookies: cfg.Auth.Session.SecureCookies, DevInsecureCookies: cfg.Auth.Session.DevInsecureCookies})
	httpSrv := &http.Server{
		Addr:              cfg.Server.ListenAddress,
		Handler:           srv.Handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(httpSrv.ListenAndServe())
}
