package pypi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/Ozark-Security-Labs/Tallow/internal/digest"
)

func TestVerifyFileBytesSHA256(t *testing.T) {
	body := []byte("wheel bytes")
	sha := sha256.Sum256(body)
	v, registry, local, err := VerifyFileBytes("pypi:pkg@1:wheel", map[string]string{"sha256": hex.EncodeToString(sha[:])}, body)
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != Verified || v.Source != "pypi-json-api" || registry[digest.AlgorithmSHA256] == "" || local[digest.AlgorithmSHA256] == "" {
		t.Fatalf("unexpected verification %#v %#v %#v", v, registry, local)
	}
}

func TestVerifyFileBytesBLAKE2bAdvertised(t *testing.T) {
	body := []byte("sdist bytes")
	sha := sha256.Sum256(body)
	blake := blake2b256Hex(body)
	_, registry, local, err := VerifyFileBytes("pypi:pkg@1:sdist", map[string]string{"sha256": hex.EncodeToString(sha[:]), "blake2b_256": blake}, body)
	if err != nil {
		t.Fatal(err)
	}
	if registry["blake2b_256"] != blake || local["blake2b_256"] != blake {
		t.Fatalf("blake2b not captured registry=%#v local=%#v", registry, local)
	}
}

func TestVerifyFileBytesMissingAndMismatch(t *testing.T) {
	v, registry, local, err := VerifyFileBytes("pypi:pkg@1", nil, []byte("bytes"))
	if err != nil || v.Status != "unverified_missing_registry_hash" || len(registry) != 0 || local[digest.AlgorithmSHA256] == "" {
		t.Fatalf("unexpected missing result %#v %#v %#v err=%v", v, registry, local, err)
	}
	_, _, _, err = VerifyFileBytes("pypi:pkg@1", map[string]string{"sha256": strings.Repeat("0", 64)}, []byte("bytes"))
	var mismatch *digest.MismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("want mismatch got %T %v", err, err)
	}
}

func TestArtifactKind(t *testing.T) {
	if ArtifactKind("sdist") != ArtifactKindSdist || ArtifactKind("bdist_wheel") != ArtifactKindWheel {
		t.Fatal("kind mapping failed")
	}
}
