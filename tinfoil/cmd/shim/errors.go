package main

import (
	"encoding/json"
	"net/http"
)

// Error type strings returned in API error responses, following OpenAI's
// taxonomy so client SDKs classify shim errors the same way they classify
// upstream ones. See https://platform.openai.com/docs/guides/error-codes
const (
	errTypeInvalidRequest     = "invalid_request_error"
	errTypeServiceUnavailable = "service_unavailable_error"
	errTypeServer             = "server_error"
)

// Machine-readable error codes carried in the `code` field. Codes shared
// with OpenAI keep OpenAI's spelling.
const (
	errCodeNotFound               = "not_found"
	errCodeUpstreamUnreachable    = "upstream_unreachable"
	errCodeServiceStarting        = "service_starting"
	errCodeServiceFailed          = "service_failed"
	errCodeInvalidNonce           = "invalid_nonce"
	errCodeAttestationUnavailable = "attestation_unavailable"
)

// Client-facing error messages, aligned with OpenAI's standard error messages
// where applicable.
const (
	errMsgServerError            = "The server had an error while processing your request."
	errMsgUpstreamUnreachable    = "The workload service is temporarily unreachable. Please try again."
	errMsgNotFound               = "Not found."
	errMsgServiceStarting        = "The service is starting. Please try again shortly."
	errMsgServiceFailed          = "The service failed to start."
	errMsgInvalidNonce           = "Invalid nonce: must be exactly 32 bytes (64 hex chars)."
	errMsgCollateralUnavailable  = "Attestation collateral is temporarily unavailable."
	errMsgGPUEvidenceUnavailable = "GPU attestation evidence is unavailable."
	errMsgAttestationBuildFailed = "Failed to build attestation."
)

// serviceStartingRetryAfterSeconds is the Retry-After hint sent while boot
// is still in progress.
const serviceStartingRetryAfterSeconds = 5

// apiError is an error response in OpenAI's format. param and code are
// emitted as JSON null when empty, matching OpenAI's envelope.
type apiError struct {
	status  int
	errType string
	code    string
	message string
}

var (
	errServer = apiError{
		status:  http.StatusInternalServerError,
		errType: errTypeServer,
		message: errMsgServerError,
	}
	errUpstreamUnreachable = apiError{
		status:  http.StatusBadGateway,
		errType: errTypeServer,
		code:    errCodeUpstreamUnreachable,
		message: errMsgUpstreamUnreachable,
	}
	errNotFound = apiError{
		status:  http.StatusNotFound,
		errType: errTypeInvalidRequest,
		code:    errCodeNotFound,
		message: errMsgNotFound,
	}
	errServiceStarting = apiError{
		status:  http.StatusServiceUnavailable,
		errType: errTypeServiceUnavailable,
		code:    errCodeServiceStarting,
		message: errMsgServiceStarting,
	}
	errServiceFailed = apiError{
		status:  http.StatusServiceUnavailable,
		errType: errTypeServiceUnavailable,
		code:    errCodeServiceFailed,
		message: errMsgServiceFailed,
	}
	errInvalidNonce = apiError{
		status:  http.StatusBadRequest,
		errType: errTypeInvalidRequest,
		code:    errCodeInvalidNonce,
		message: errMsgInvalidNonce,
	}
	errCollateralUnavailable = apiError{
		status:  http.StatusServiceUnavailable,
		errType: errTypeServiceUnavailable,
		code:    errCodeAttestationUnavailable,
		message: errMsgCollateralUnavailable,
	}
	errGPUEvidenceUnavailable = apiError{
		status:  http.StatusInternalServerError,
		errType: errTypeServer,
		code:    errCodeAttestationUnavailable,
		message: errMsgGPUEvidenceUnavailable,
	}
	errAttestationBuildFailed = apiError{
		status:  http.StatusInternalServerError,
		errType: errTypeServer,
		code:    errCodeAttestationUnavailable,
		message: errMsgAttestationBuildFailed,
	}
)

// errorBody mirrors OpenAI's error object. Param and Code serialize as null
// when unset.
type errorBody struct {
	Message string  `json:"message"`
	Type    string  `json:"type"`
	Param   *string `json:"param"`
	Code    *string `json:"code"`
}

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (e apiError) envelope() errorEnvelope {
	return errorEnvelope{Error: errorBody{
		Message: e.message,
		Type:    e.errType,
		Code:    nullableString(e.code),
	}}
}

func writeAPIError(w http.ResponseWriter, e apiError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.status)
	json.NewEncoder(w).Encode(e.envelope())
}
