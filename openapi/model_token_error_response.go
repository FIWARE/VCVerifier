package openapi

// TokenErrorResponse is the error response of the token endpoint (RFC 6749 §5.2).
type TokenErrorResponse struct {
	Error string `json:"error"`

	ErrorDescription string `json:"error_description,omitempty"`
}
