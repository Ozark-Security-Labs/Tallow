package scm

import "errors"

var (
	ErrNotFound        = errors.New("scm not found")
	ErrRateLimited     = errors.New("scm rate limited")
	ErrUnauthorized    = errors.New("scm unauthorized")
	ErrForbidden       = errors.New("scm forbidden")
	ErrInvalidResponse = errors.New("scm invalid response")
)
