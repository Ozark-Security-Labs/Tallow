.PHONY: test test-integration test-race generate generate-check schema-validate compose-check

test:
	go test ./...

test-integration:
	go test -tags=integration ./...

test-race:
	go test -race ./internal/scheduler/...

generate:
	go generate ./...
	@command -v sqlc >/dev/null 2>&1 || { echo "sqlc is required; install sqlc to regenerate database bindings" >&2; exit 1; }
	sqlc generate

generate-check:
	./scripts/generate-check.sh

schema-validate:
	./scripts/validate-schemas.sh

compose-check:
	docker compose config
