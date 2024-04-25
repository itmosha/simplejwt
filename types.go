package simplejwt

import "github.com/golang-jwt/jwt"

const (
	// DefaultAccessTTL is the default access token TTL (Time-To-Live) in seconds.
	DefaultAccessTTL = 600
	// DefaultRefreshTTL is the default refresh token TTL (Time-To-Live) in seconds.
	DefaultRefreshTTL = 3600
)

// TokenPair represents a JWT token pair (access and refresh tokens) used for authentication.
type TokenPair struct {
	AccessToken  Token
	RefreshToken Token
}

// Token represent a JWT token with its expiration time and issued time.
type Token struct {
	Token string
	Exp   int64
	Iat   int64
}

// JWTOptions represents options for setting up the JWT client.
type JWTOptions struct {
	// AccessTTL is the access token TTL (Time-To-Live) in seconds.
	// If not provided, the default value is 600 (10 minutes).
	AccessTTL int
	// RefreshTTL is the refresh token TTL (Time-To-Live) in seconds.
	// If not provided, the default value is 3600 (1 hour).
	RefreshTTL int

	// SigningMethod is the signing method used for signing the JWT tokens.
	// If not provided, the default value is HS256.
	// See https://godoc.org/github.com/golang-jwt/jwt#SigningMethod for available signing methods.
	SigningMethod jwt.SigningMethod
}
