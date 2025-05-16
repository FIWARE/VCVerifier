package common

import (
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type TokenSigner interface {
	Sign(t jwt.Token, options ...jwt.SignOption) ([]byte, error)
}

type JwtTokenSigner struct{}

func (JwtTokenSigner) Sign(t jwt.Token, options ...jwt.SignOption) ([]byte, error) {
	return jwt.Sign(t, options...)
}
