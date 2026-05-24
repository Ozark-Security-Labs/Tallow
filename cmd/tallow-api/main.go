package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/api"
	"github.com/Ozark-Security-Labs/Tallow/internal/config"
	"github.com/Ozark-Security-Labs/Tallow/internal/events"
	"github.com/jackc/pgx/v5"
)

func main() {
	cfg, err := config.LoadFromEnvironment()
	if err != nil {
		log.Fatal(err)
	}
	checks := map[string]api.Check{
		"postgres": func(ctx context.Context) error {
			cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			conn, err := pgx.Connect(cctx, cfg.Postgres.DSN)
			if err != nil {
				return err
			}
			defer conn.Close(cctx)
			return conn.Ping(cctx)
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
	srv := api.New(cfg, slog.Default(), checks)
	httpSrv := &http.Server{
		Addr:              cfg.Server.ListenAddress,
		Handler:           srv.Handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(httpSrv.ListenAndServe())
}
