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

func TestFetchMetadataRejectsOversizeBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"info":{"name":"pkg"},"releases":{"1.0.0":[]}}`))
	}))
	defer srv.Close()
	client := NewClient(srv.URL, srv.Client())
	client.MaxDownloadBytes = 8
	if _, err := client.FetchMetadata(context.Background(), "pkg"); err == nil {
		t.Fatal("want oversize metadata error")
	}
}

func TestFetchMetadataRejectsTrailingJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"info":{"name":"pkg"},"releases":{}} {}`))
	}))
	defer srv.Close()
	if _, err := NewClient(srv.URL, srv.Client()).FetchMetadata(context.Background(), "pkg"); err == nil {
		t.Fatal("want trailing JSON error")
	}
}

func TestFetchMetadataRejectsRedirectToUntrustedHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/pypi/pkg/json", http.StatusFound)
	}))
	defer srv.Close()
	if _, err := NewClient(srv.URL, srv.Client()).FetchMetadata(context.Background(), "pkg"); err == nil {
		t.Fatal("want redirect validation error")
	}
}

func TestObservePropagatesStorageURIErrors(t *testing.T) {
	body := []byte("wheel bytes")
	sha := sha256.Sum256(body)
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pypi/pkg/json":
			fmt.Fprintf(w, `{"info":{"name":"pkg","version":"1.0.0"},"releases":{"1.0.0":[{"filename":"bad..whl","packagetype":"bdist_wheel","url":"%s/files/bad..whl","digests":{"sha256":"%s"}}]}}`, base, hex.EncodeToString(sha[:]))
		case "/files/bad..whl":
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	base = srv.URL
	if _, err := NewClient(srv.URL, srv.Client()).Observe(context.Background(), "pkg", "1.0.0"); err == nil {
		t.Fatal("want storage URI error")
	}
}

func TestObserveNoSupportedArtifacts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"info":{"name":"pkg","version":"1.0.0"},"releases":{"1.0.0":[{"filename":"pkg.egg","packagetype":"bdist_egg","url":"http://example.invalid/pkg.egg"}]}}`))
	}))
	defer srv.Close()
	if _, err := NewClient(srv.URL, srv.Client()).Observe(context.Background(), "pkg", "1.0.0"); err == nil {
		t.Fatal("want no supported artifacts error")
	}
}
