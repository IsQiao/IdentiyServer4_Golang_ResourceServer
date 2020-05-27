package id4rs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// AuthVerifier auth verifier instance
type AuthVerifier struct {
	ctx      context.Context
	issuer   string
	audience string
	provider *oidc.Provider
}

// NewAuthVerifier new a auth verifier
func NewAuthVerifier(ctx context.Context, issuer string, audience string) (*AuthVerifier, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}

	authVerifier := AuthVerifier{
		ctx,
		issuer,
		audience,
		provider,
	}

	return &authVerifier, nil
}

// GetBearerToken get Authorization bearer token
func GetBearerToken(req *http.Request) (string, error) {
	authHeaderString := req.Header.Get("Authorization")
	if authHeaderString == "" {
		return "", fmt.Errorf("bad request")
	}
	bearerToken := authHeaderString[len("Bearer "):]

	return bearerToken, nil
}

// GetUserInfo get user info by jwt token
func (v *AuthVerifier) GetUserInfo(jwt string) (*oidc.UserInfo, error) {
	oauth2Token := oauth2.Token{
		AccessToken: jwt,
	}
	userInfo, err := v.provider.UserInfo(v.ctx, oauth2.StaticTokenSource(&oauth2Token))
	if err != nil {
		return nil, err
	}
	return userInfo, nil
}

// GetUserInfoByHeader get user info by header
func (v *AuthVerifier) GetUserInfoByHeader(req *http.Request) (*oidc.UserInfo, error) {
	bearerToken, err := GetBearerToken(req)
	if err != nil {
		return nil, err
	}

	return v.GetUserInfo(bearerToken)
}

// GetUserClaims get user info claims by user info
func GetUserClaims(u *oidc.UserInfo) (map[string]interface{}, error) {
	if u == nil {
		return nil, fmt.Errorf("user info is invalid")
	}
	var userClaims map[string]interface{}
	u.Claims(&userClaims)
	return userClaims, nil
}

func contains(arr []interface{}, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

// Verify check the jwt token is valid
func (v *AuthVerifier) Verify(jwt string) error {
	err := isValidJwt(jwt)
	if err != nil {
		return err
	}

	payload, err := getPayload(jwt)
	if err != nil {
		return err
	}

	issuer := payload["iss"].(interface{})
	if issuer != v.issuer {
		return fmt.Errorf("the `Issuer` was not able to be validated")
	}

	audienceScope := payload["aud"].([]interface{})
	if !contains(audienceScope, v.audience) {
		return fmt.Errorf("the `Audience` was not able to be validated")
	}

	IDVerifier := v.provider.Verifier(&oidc.Config{ClientID: v.audience})
	IDToken, err := IDVerifier.Verify(v.ctx, jwt)
	if IDToken != nil && err != nil {
		return err
	}
	return nil
}

func isValidJwt(jwt string) error {
	if jwt == "" {
		return fmt.Errorf("you must provide a jwt to verify")
	}

	var jwtRegex = regexp.MustCompile(`[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.?([a-zA-Z0-9-_]+)[/a-zA-Z0-9-_]+?$`).MatchString
	if !jwtRegex(jwt) {
		return fmt.Errorf("token must contain at least 1 period ('.') and only characters 'a-Z 0-9 _'")
	}

	return nil
}

func getPayload(jwt string) (map[string]interface{}, error) {
	parts := strings.Split(jwt, ".")
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("the tokens payload does not appear to be a base64 encoded string")
	}

	var payloadObject map[string]interface{}
	isHeaderJSON := json.Unmarshal(payloadBytes, &payloadObject) == nil
	if isHeaderJSON == false {
		return nil, fmt.Errorf("the tokens payload is not a json object")
	}
	return payloadObject, nil
}
