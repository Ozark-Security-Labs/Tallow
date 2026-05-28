package auth

import (
	"errors"

	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
)

var (
	ErrInvalidCredentials    = tallowerr.New(tallowerr.CodeAuth, "invalid credentials")
	ErrProviderDisabled      = tallowerr.New(tallowerr.CodeAuthProviderDisabled, "auth provider disabled")
	ErrProviderMisconfigured = errors.New("auth provider misconfigured")
	ErrInvalidOAuthState     = tallowerr.New(tallowerr.CodeInvalidOAuthState, "invalid oauth state")
	ErrOAuthExchangeFailed   = tallowerr.New(tallowerr.CodeOAuthExchangeFailed, "oauth exchange failed")
	ErrIdentityNotAllowed    = tallowerr.New(tallowerr.CodeIdentityNotAllowed, "identity is not allowed")
)

func WrapProviderError(err error) error {
	if err == nil {
		return nil
	}
	var terr *tallowerr.Error
	if errors.As(err, &terr) {
		return terr
	}
	return tallowerr.Wrap(tallowerr.CodeAuth, "auth provider failed", err)
}
