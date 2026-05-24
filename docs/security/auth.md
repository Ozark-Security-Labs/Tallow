# Authentication Architecture

Tallow uses an auth provider abstraction.

## Initial providers

- Local email/password auth.
- GitHub OAuth without requiring an external auth service.

## Future providers

- Generic OIDC/JWT.
- Clerk.
- WorkOS.

## Internal model

Tallow keeps local `users`, `identities`, `sessions`, and `roles` records even when external auth is used. Roles: `admin`, `analyst`, `viewer`.

Provider implementations should authenticate identity; authorization remains inside Tallow.
