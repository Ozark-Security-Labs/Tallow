package tallowerr

import (
	"encoding/json"
	"errors"
	"net/http"
)

type Code string

const (
	CodeValidation          Code = "validation_failed"
	CodeAuth                Code = "auth_failed"
	CodeHashMismatch        Code = "hash_mismatch"
	CodeUnpackRejected      Code = "unpack_rejected"
	CodeAnalyzerFailed      Code = "analyzer_failed"
	CodeRegistryUnavailable Code = "registry_unavailable"
	CodeDatabaseUnavailable Code = "database_unavailable"
	CodeEventBusUnavailable Code = "event_bus_unavailable"
	CodeNotFound            Code = "not_found"
	CodeInternal            Code = "internal_error"
	CodeNotImplemented      Code = "not_implemented"
)

type Error struct {
	Code       Code
	Message    string
	SafeDetail string
	Cause      error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return string(e.Code) + ": " + e.Message
	}
	return string(e.Code)
}
func (e *Error) Unwrap() error         { return e.Cause }
func New(code Code, msg string) *Error { return &Error{Code: code, Message: msg} }
func Wrap(code Code, msg string, cause error) *Error {
	return &Error{Code: code, Message: msg, Cause: cause}
}
func IsCode(err error, code Code) bool { var e *Error; return errors.As(err, &e) && e.Code == code }
func HTTPStatus(code Code) int {
	switch code {
	case CodeValidation:
		return http.StatusBadRequest
	case CodeAuth:
		return http.StatusUnauthorized
	case CodeDatabaseUnavailable, CodeEventBusUnavailable, CodeRegistryUnavailable:
		return http.StatusServiceUnavailable
	case CodeNotImplemented:
		return http.StatusNotImplemented
	case CodeNotFound:
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

type Envelope struct {
	Error ErrorBody `json:"error"`
}
type ErrorBody struct {
	Code      Code   `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
	Details   string `json:"details,omitempty"`
}

func JSONEnvelope(err error, requestID string) Envelope {
	var e *Error
	if !errors.As(err, &e) {
		e = New(CodeInternal, "internal error")
	}
	return Envelope{Error: ErrorBody{Code: e.Code, Message: e.Message, RequestID: requestID, Details: e.SafeDetail}}
}
func (e Envelope) Marshal() []byte { b, _ := json.Marshal(e); return b }
