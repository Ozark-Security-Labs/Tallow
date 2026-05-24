package npm

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/Ozark-Security-Labs/Tallow/internal/digest"
)

func TestVerifyTarballBytesSRI(t *testing.T) {
	body := []byte("fixture tarball")
	sha := sha512.Sum512(body)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(sha[:])
	v, registry, local, err := VerifyTarballBytes("npm:pkg@1", integrity, "", body)
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != VerificationVerified || v.Trust != TrustRegistrySRI || registry[digest.AlgorithmSHA512] == "" || local[digest.AlgorithmSHA256] == "" {
		t.Fatalf("unexpected verification %#v registry=%#v local=%#v", v, registry, local)
	}
}

func TestVerifyTarballBytesShasumFallback(t *testing.T) {
	body := []byte("fixture tarball")
	sha := sha1.Sum(body)
	v, registry, _, err := VerifyTarballBytes("npm:pkg@1", "", hex.EncodeToString(sha[:]), body)
	if err != nil {
		t.Fatal(err)
	}
	if v.Trust != TrustShasumFallback || registry[digest.AlgorithmSHA1] == "" {
		t.Fatalf("unexpected shasum fallback %#v %#v", v, registry)
	}
}

func TestVerifyTarballBytesMismatch(t *testing.T) {
	_, _, _, err := VerifyTarballBytes("npm:pkg@1", "", strings.Repeat("0", 40), []byte("fixture tarball"))
	var mismatch *digest.MismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("want mismatch got %T %v", err, err)
	}
}

func TestVerifyTarballBytesMissingHash(t *testing.T) {
	v, registry, local, err := VerifyTarballBytes("npm:pkg@1", "", "", []byte("fixture tarball"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != "unverified_missing_registry_hash" || len(registry) != 0 || local[digest.AlgorithmSHA256] == "" {
		t.Fatalf("unexpected missing hash result %#v %#v %#v", v, registry, local)
	}
}
