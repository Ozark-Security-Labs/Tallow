package digest

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"
)

const (
	AlgorithmSHA1   = "sha1"
	AlgorithmSHA256 = "sha256"
	AlgorithmSHA512 = "sha512"
)

type Expected struct {
	Algorithm  string
	Hex        string
	Source     string
	ArtifactID string
}

type Result struct {
	Algorithm string
	Hex       string
	Matched   bool
	Source    string
}

type MismatchError struct {
	Algorithm  string
	Expected   string
	Actual     string
	Source     string
	ArtifactID string
}

func (e *MismatchError) Error() string {
	id := e.ArtifactID
	if id == "" {
		id = "unknown"
	}
	return fmt.Sprintf("digest mismatch for %s: %s expected %s actual %s", id, e.Algorithm, e.Expected, e.Actual)
}

type UnsupportedAlgorithmError struct{ Algorithm string }

func (e UnsupportedAlgorithmError) Error() string {
	return "unsupported digest algorithm: " + e.Algorithm
}

func NewHash(algorithm string) (hash.Hash, error) {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case AlgorithmSHA1:
		return sha1.New(), nil
	case AlgorithmSHA256:
		return sha256.New(), nil
	case AlgorithmSHA512:
		return sha512.New(), nil
	default:
		return nil, UnsupportedAlgorithmError{Algorithm: algorithm}
	}
}

func Compute(r io.Reader, algorithm string) (string, error) {
	h, err := NewHash(algorithm)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func Verify(r io.Reader, expected Expected) (Result, error) {
	alg := strings.ToLower(strings.TrimSpace(expected.Algorithm))
	want := strings.ToLower(strings.TrimSpace(expected.Hex))
	actual, err := Compute(r, alg)
	if err != nil {
		return Result{}, err
	}
	res := Result{Algorithm: alg, Hex: actual, Matched: actual == want, Source: expected.Source}
	if !res.Matched {
		return res, &MismatchError{Algorithm: alg, Expected: want, Actual: actual, Source: expected.Source, ArtifactID: expected.ArtifactID}
	}
	return res, nil
}

func ComputeSet(r io.Reader, algorithms ...string) (map[string]string, error) {
	if len(algorithms) == 0 {
		algorithms = []string{AlgorithmSHA256}
	}
	var hs []hash.Hash
	out := make(map[string]string, len(algorithms))
	for _, alg := range algorithms {
		h, err := NewHash(alg)
		if err != nil {
			return nil, err
		}
		hs = append(hs, h)
	}
	writers := make([]io.Writer, len(hs))
	for i := range hs {
		writers[i] = hs[i]
	}
	if _, err := io.Copy(io.MultiWriter(writers...), r); err != nil {
		return nil, err
	}
	for i, alg := range algorithms {
		out[strings.ToLower(strings.TrimSpace(alg))] = hex.EncodeToString(hs[i].Sum(nil))
	}
	return out, nil
}
