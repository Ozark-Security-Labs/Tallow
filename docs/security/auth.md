# Authentication Architecture

Tallow uses an auth provider abstraction. Provider implementations authenticate an identity; Tallow-owned sessions and RBAC authorize every protected action.

## AuthProvider interface

Provider-agnostic route handlers depend on `auth.Manager` and these interfaces, not on concrete local or GitHub implementations:

```go
type Provider interface {
    Name() string
    LoginMethods(ctx context.Context) ([]LoginMethod, error)
}

type PasswordProvider interface {
    Provider
    AuthenticatePassword(ctx context.Context, email, password string) (*Identity, error)
}

type OAuthProvider interface {
    Provider
    BeginOAuth(ctx context.Context, redirectPath string) (*OAuthStart, error)
    CompleteOAuth(ctx context.Context, query url.Values) (*Identity, error)
}
```

`auth.Manager` sorts provider names before listing login methods so UI behavior is deterministic. Provider-specific failures are mapped to stable API error codes such as `auth_failed`, `auth_provider_disabled`, `invalid_oauth_state`, `oauth_exchange_failed`, and `identity_not_allowed`.

## Initial providers

- Local email/password auth.
- GitHub OAuth without requiring an external auth service.

## Future providers

The provider boundary is intentionally compatible with future Generic OIDC/JWT, Clerk, and WorkOS providers. Those implementations should return a normalized `Identity` and must not decide Tallow authorization policy.

## Internal model

Tallow keeps local `users`, `identities`, `sessions`, and `roles` records even when external auth is used. Roles: `admin`, `analyst`, `viewer`.

## Handler boundary

Route handlers receive provider/session/RBAC interfaces. Provider-specific code must stay inside `internal/auth/<provider>` packages so GitHub, local, future OIDC, Clerk, or WorkOS details do not leak into API handlers.

## Foundation status

Foundation did not implement production authentication or authorization. Milestone 5 adds the provider abstraction first, then local sessions, GitHub OAuth, and RBAC enforcement. Until those pieces are configured, deployments must bind locally or place Tallow behind operator-controlled access.
