package api

import (
	"github.com/Ozark-Security-Labs/Tallow/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNarrativeAPIDisabled(t *testing.T) {
	s := New(config.Default(), nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/narratives", strings.NewReader(`{"findings":[{"ID":"F-1"}]}`))
	rr := httptest.NewRecorder()
	s.createNarrative(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "disabled") {
		t.Fatal(rr.Body.String())
	}
}
