package tallowerr

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestCodesWrapAndStatus(t *testing.T) {
	err := Wrap(CodeValidation, "bad", errors.New("raw secret"))
	if !IsCode(err, CodeValidation) {
		t.Fatal("code mismatch")
	}
	if HTTPStatus(CodeValidation) != http.StatusBadRequest {
		t.Fatal("status")
	}
	if HTTPStatus(CodeHashMismatch) != 500 {
		t.Fatal("hash status")
	}
}
func TestJSONEnvelopeSafe(t *testing.T) {
	env := JSONEnvelope(&Error{Code: CodeUnpackRejected, Message: "rejected", SafeDetail: "path traversal"}, "r1")
	s := string(env.Marshal())
	for _, want := range []string{"unpack_rejected", "request_id", "path traversal"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in %s", want, s)
		}
	}
}
