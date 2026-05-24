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

## Foundation status

Foundation does not implement production authentication or authorization. Deployments must bind locally or place Tallow behind operator-controlled access until the auth boundary lands. Future auth must protect API, CLI administration paths, notification configuration, and tenant/user isolation.
