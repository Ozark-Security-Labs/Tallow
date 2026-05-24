package pypi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestObserveVersionWheelSdistAndYanked(t *testing.T) {
	wheel := []byte("wheel bytes")
	sdist := []byte("sdist bytes")
	wsha := sha256.Sum256(wheel)
	ssha := sha256.Sum256(sdist)
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pypi/pkg/json":
			fmt.Fprintf(w, `{"info":{"name":"pkg","version":"1.0.0"},"releases":{"1.0.0":[{"filename":"pkg-1.0.0-py3-none-any.whl","packagetype":"bdist_wheel","url":"%s/files/pkg.whl","digests":{"sha256":"%s"},"upload_time_iso_8601":"2026-05-24T00:00:00Z"},{"filename":"pkg-1.0.0.tar.gz","packagetype":"sdist","url":"%s/files/pkg.tar.gz","digests":{"sha256":"%s"},"yanked":true,"yanked_reason":"bad metadata","upload_time_iso_8601":"2026-05-24T01:00:00Z"}]}}`, base, hex.EncodeToString(wsha[:]), base, hex.EncodeToString(ssha[:]))
		case "/files/pkg.whl":
			_, _ = w.Write(wheel)
		case "/files/pkg.tar.gz":
			_, _ = w.Write(sdist)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	base = srv.URL
	got, err := NewClient(srv.URL, srv.Client()).Observe(context.Background(), "pkg", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Kind != ArtifactKindWheel || got[1].Kind != ArtifactKindSdist || !got[1].Yanked || got[0].StorageURI == "" {
		t.Fatalf("unexpected artifacts %#v", got)
	}
	if !got[0].UploadedAt.Equal(time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("upload time not parsed: %s", got[0].UploadedAt)
	}
}

func TestObserveMissingVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"info":{"name":"pkg"},"releases":{}}`))
	}))
	defer srv.Close()
	_, err := NewClient(srv.URL, srv.Client()).Observe(context.Background(), "pkg", "9.9.9")
	if err == nil {
		t.Fatal("want missing version")
	}
}
