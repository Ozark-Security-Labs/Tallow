package npm

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/digest"
)

func TestObserveScopedPackageVersion(t *testing.T) {
	body := []byte("fixture tarball bytes")
	sha := sha512.Sum512(body)
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/@scope/pkg":
			fmt.Fprintf(w, `{"name":"@scope/pkg","versions":{"1.2.3":{"name":"@scope/pkg","version":"1.2.3","dist":{"tarball":"%s/@scope/pkg/-/pkg-1.2.3.tgz","integrity":"sha512-%s"}}},"time":{"1.2.3":"2026-05-24T00:00:00Z"}}`, base, base64.StdEncoding.EncodeToString(sha[:]))
		case "/@scope/pkg/-/pkg-1.2.3.tgz":
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	base = srv.URL
	got, err := NewClient(srv.URL, srv.Client()).Observe(context.Background(), "@scope/pkg", "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if got.Package != "@scope/pkg" || got.Filename != "pkg-1.2.3.tgz" || got.Verification.Status != VerificationVerified || got.LocalHashes[digest.AlgorithmSHA256] == "" || got.StorageURI == "" {
		t.Fatalf("unexpected artifact %#v", got)
	}
	if !got.PublishedAt.Equal(time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("publish time not parsed: %s", got.PublishedAt)
	}
}

func TestObserveMissingVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"pkg","versions":{}}`))
	}))
	defer srv.Close()
	_, err := NewClient(srv.URL, srv.Client()).Observe(context.Background(), "pkg", "9.9.9")
	if err == nil {
		t.Fatal("want missing version error")
	}
}
