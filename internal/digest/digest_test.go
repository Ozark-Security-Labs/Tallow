package digest

import (
	"errors"
	"strings"
	"testing"
)

func TestComputeSetStreamsDigests(t *testing.T) {
	got, err := ComputeSet(strings.NewReader("hello"), AlgorithmSHA1, AlgorithmSHA256, AlgorithmSHA512)
	if err != nil {
		t.Fatal(err)
	}
	if got[AlgorithmSHA1] != "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" {
		t.Fatalf("sha1 %s", got[AlgorithmSHA1])
	}
	if got[AlgorithmSHA256] != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("sha256 %s", got[AlgorithmSHA256])
	}
	if got[AlgorithmSHA512] == "" {
		t.Fatal("missing sha512")
	}
}

func TestVerifyMatchMismatchUnsupported(t *testing.T) {
	res, err := Verify(strings.NewReader("hello"), Expected{Algorithm: AlgorithmSHA256, Hex: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", ArtifactID: "pkg@1"})
	if err != nil || !res.Matched {
		t.Fatalf("match err=%v res=%#v", err, res)
	}
	_, err = Verify(strings.NewReader("hello"), Expected{Algorithm: AlgorithmSHA256, Hex: strings.Repeat("0", 64), ArtifactID: "pkg@1"})
	var mismatch *MismatchError
	if !errors.As(err, &mismatch) || mismatch.ArtifactID != "pkg@1" || mismatch.Actual == "" {
		t.Fatalf("want typed mismatch got %T %v", err, err)
	}
	_, err = Verify(strings.NewReader("hello"), Expected{Algorithm: "md5", Hex: "x"})
	var unsupported UnsupportedAlgorithmError
	if !errors.As(err, &unsupported) {
		t.Fatalf("want unsupported got %T %v", err, err)
	}
}
