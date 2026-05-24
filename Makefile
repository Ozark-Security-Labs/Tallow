.PHONY: test test-integration test-race generate generate-check schema-validate compose-check

test:
	go test ./...

test-integration:
	go test -tags=integration ./...

test-race:
	go test -race ./internal/scheduler/...

generate:
	go generate ./...
	@if command -v sqlc >/dev/null 2>&1; then sqlc generate; else echo "sqlc not installed; install sqlc to regenerate database bindings"; fi

generate-check:
	./scripts/generate-check.sh

schema-validate:
	./scripts/validate-schemas.sh

compose-check:
	docker compose config
