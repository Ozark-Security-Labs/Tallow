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

## GitHub OAuth

The GitHub provider is built in and does not require Clerk, WorkOS, or another hosted auth service. Operators configure `client_id`, a secret-backed client secret, callback URL, and optional allow hooks:

- `allowed_orgs`: permits any member of the listed GitHub organizations.
- `allowed_teams`: permits members of listed `org/team-slug` teams.

OAuth state contains provider, nonce, issue time, expiry time, and redirect path. It is HMAC-signed, expires, and is rejected on replay in the running process. Callback handling validates state before exchanging the code, maps GitHub `/user` plus primary `/user/emails` data into a normalized identity, and never logs access tokens or client secrets.

## Future providers

The provider boundary is intentionally compatible with future Generic OIDC/JWT, Clerk, and WorkOS providers. Those implementations should return a normalized `Identity` and must not decide Tallow authorization policy.

## Local auth and sessions

The local provider supports a bootstrap admin configured for development or first-run setup. The bootstrap admin is only valid until a persisted admin exists. Persisted local users authenticate by email and a versioned bcrypt password hash; plaintext passwords are never accepted as stored hashes.

Sessions use random bearer tokens stored server-side as SHA-256 token hashes. The browser receives only the `tallow_session` cookie. Cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` unless `auth.session.dev_insecure_cookies` is explicitly enabled for local development. Logout revokes the server-side session and expires the browser cookie.

## Internal model

Tallow keeps local `users`, `identities`, `sessions`, and `roles` records even when external auth is used. Roles: `admin`, `analyst`, `viewer`.

## Handler boundary

Route handlers receive provider/session/RBAC interfaces. Provider-specific code must stay inside `internal/auth/<provider>` packages so GitHub, local, future OIDC, Clerk, or WorkOS details do not leak into API handlers.

## Foundation status

Foundation did not implement production authentication or authorization. Milestone 5 adds the provider abstraction first, then local sessions, GitHub OAuth, and RBAC enforcement. Until those pieces are configured, deployments must bind locally or place Tallow behind operator-controlled access.
