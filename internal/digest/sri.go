package digest

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
)

type SRIClaim struct {
	Algorithm string
	Hex       string
	Base64    string
}

func ParseSRI(value string) ([]SRIClaim, error) {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) == 0 {
		return nil, UnsupportedAlgorithmError{Algorithm: ""}
	}
	claims := make([]SRIClaim, 0, len(fields))
	for _, field := range fields {
		parts := strings.SplitN(field, "-", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, UnsupportedAlgorithmError{Algorithm: field}
		}
		alg := strings.ToLower(parts[0])
		if _, err := NewHash(alg); err != nil {
			return nil, err
		}
		raw, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, err
		}
		claims = append(claims, SRIClaim{Algorithm: alg, Hex: hex.EncodeToString(raw), Base64: parts[1]})
	}
	return claims, nil
}

func PreferredSRI(value string) (Expected, error) {
	claims, err := ParseSRI(value)
	if err != nil {
		return Expected{}, err
	}
	for _, want := range []string{AlgorithmSHA512, AlgorithmSHA256, AlgorithmSHA1} {
		for _, c := range claims {
			if c.Algorithm == want {
				return Expected{Algorithm: c.Algorithm, Hex: c.Hex, Source: "sri"}, nil
			}
		}
	}
	return Expected{}, UnsupportedAlgorithmError{Algorithm: value}
}
