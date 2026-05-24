package main

import (
	"github.com/Ozark-Security-Labs/Tallow/internal/api"
	"github.com/Ozark-Security-Labs/Tallow/internal/config"
	"log"
	"log/slog"
	"net/http"
)

func main() {
	cfg, err := config.LoadFromEnvironment()
	if err != nil {
		log.Fatal(err)
	}
	srv := api.New(cfg, slog.Default(), nil)
	log.Fatal(http.ListenAndServe(cfg.Server.ListenAddress, srv.Handler))
}
