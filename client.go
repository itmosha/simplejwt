package simplejwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
)

// JWTClient represents a JWT client which can be used to perform actions on JWT tokens.
type JWTClient struct {
	// secretKey is the secret key used for signing and verifying JWT tokens.
	secretKey string

	// options is the options for setting up the JWT client.
	Options *JWTOptions
}

// NewJWTClient creates a new JWT client with the given options.
func NewJWTClient(secretKey string, opts *JWTOptions) *JWTClient {
	// set up default options
	if opts == nil {
		opts = &JWTOptions{AccessTTL: DefaultAccessTTL, RefreshTTL: DefaultRefreshTTL, SigningMethod: jwt.SigningMethodHS256}
	} else {
		if opts.AccessTTL == 0 {
			opts.AccessTTL = DefaultAccessTTL
		}
		if opts.RefreshTTL == 0 {
			opts.RefreshTTL = DefaultRefreshTTL
		}
		if opts.SigningMethod == nil {
			opts.SigningMethod = jwt.SigningMethodHS256
		}
	}

	return &JWTClient{
		secretKey: secretKey,
		Options:   opts,
	}
}

// CreateTokenPair creates a new access and refresh token pair for the given claims.
func (client *JWTClient) CreateTokenPair(claims map[string]interface{}) (tp *TokenPair, err error) {

	// create access token
	at := jwt.New(client.Options.SigningMethod)
	atClaims := at.Claims.(jwt.MapClaims)
	for k, v := range claims {
		atClaims[k] = v
	}
	atClaims["exp"] = time.Now().Add(time.Duration(client.Options.AccessTTL) * time.Second).Unix()
	atClaims["iat"] = time.Now().Unix()

	accessToken, err := at.SignedString([]byte(client.secretKey))
	if err != nil {
		return
	}

	// create refresh token
	rt := jwt.New(client.Options.SigningMethod)
	rtClaims := rt.Claims.(jwt.MapClaims)
	rtClaims["exp"] = time.Now().Add(time.Duration(client.Options.RefreshTTL) * time.Second).Unix()
	rtClaims["iat"] = time.Now().Unix()

	refreshToken, err := rt.SignedString([]byte(client.secretKey))
	if err != nil {
		return
	}

	// create token pair
	tp = &TokenPair{AccessToken: accessToken, RefreshToken: refreshToken}
	return
}

// ExtractClaims extracts the claims from the given token string.
func (client *JWTClient) extractClaims(token string) (claims jwt.MapClaims, err error) {
	_, err = jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(client.secretKey), nil
	})
	if err != nil {
		var validationError *jwt.ValidationError
		switch {
		case errors.As(err, &validationError):
			switch validationError.Errors {
			case jwt.ValidationErrorExpired:
				err = ErrTokenExpired
			case jwt.ValidationErrorSignatureInvalid:
				err = ErrSignatureInvalid
			default:
				err = ErrValidateToken
			}
		default:
			return
		}
	}
	return
}

// RefreshTokenPair refreshes the access and refresh token pair for the given claims.
// New token pair is created from provided claims, not from the old token pair in case some payload fields were changed.
func (client *JWTClient) RefreshTokenPair(tp *TokenPair, claims map[string]interface{}) (newTp *TokenPair, err error) {

	// check that access token is valid
	_, err = client.extractClaims(tp.AccessToken)
	if errors.Is(err, ErrTokenExpired) {
		err = nil
	} else if err != nil {
		return
	}

	// check that refresh token is valid and not expired
	_, err = client.extractClaims(tp.RefreshToken)
	if err != nil {
		return
	}
	newTp, err = client.CreateTokenPair(claims)
	return
}
