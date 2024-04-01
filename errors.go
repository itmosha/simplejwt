package simplejwt

import "errors"

var (
	ErrTokenExpired     = errors.New("token is expired")
	ErrSignatureInvalid = errors.New("token signature is invalid")
	ErrValidateToken    = errors.New("could not validate token")
)
