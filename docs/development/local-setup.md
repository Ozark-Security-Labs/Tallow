# Local setup

Copy `.env.example` if desired. Start dependencies with `docker compose up -d postgres nats`; start the API with `docker compose up --build api`. Reset with `docker compose down -v`. No cloud credentials are required. Default services must remain unprivileged and must not mount the Docker socket.

Run migrations with `tallow db migrate --config configs/tallow.example.yml` after Postgres is available.
