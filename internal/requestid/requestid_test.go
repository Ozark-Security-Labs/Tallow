package requestid

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewValid(t *testing.T) {
	if !Valid(New()) {
		t.Fatal("invalid new id")
	}
}
func TestMiddlewarePreserveAndReplace(t *testing.T) {
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { id, _ := FromContext(r.Context()); w.Write([]byte(id)) }))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set(Header, "abc-123")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get(Header) != "abc-123" || w.Body.String() != "abc-123" {
		t.Fatal("not preserved")
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set(Header, "bad id\n")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get(Header) == "bad id\n" || !Valid(w.Header().Get(Header)) {
		t.Fatal("not replaced")
	}
}
