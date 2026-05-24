package requestid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"regexp"
)

const Header = "X-Request-ID"

type key struct{}

var valid = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func New() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func Valid(id string) bool { return valid.MatchString(id) }
func WithContext(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, key{}, id)
}
func FromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(key{}).(string)
	return v, ok && v != ""
}
func SlogAttr(ctx context.Context) slog.Attr {
	if id, ok := FromContext(ctx); ok {
		return slog.String("request_id", id)
	}
	return slog.String("request_id", "")
}
