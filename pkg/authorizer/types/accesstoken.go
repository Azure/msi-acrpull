package types

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type AccessToken string

func (t AccessToken) GetTokenTenantId() (string, error) {
	claims, err := t.GetTokenClaims()
	if err != nil {
		return "", err
	}
	tenantID, ok := claims["tid"].(string)
	if ok {
		return tenantID, nil
	}

	tenantID, ok = claims["tenant"].(string)
	if ok {
		return tenantID, nil
	}

	return "", fmt.Errorf("token has no tenant ID")
}

func (t AccessToken) GetTokenClaims() (jwt.MapClaims, error) {
	p := &jwt.Parser{SkipClaimsValidation: true}

	token, _, err := p.ParseUnverified(string(t), jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claim type from token")
	}

	return claims, nil
}

func (t AccessToken) GetTokenExp() (time.Time, error) {
	claims, err := t.GetTokenClaims()
	if err != nil {
		return time.Time{}, err
	}

	switch exp := claims["exp"].(type) {
	case float64:
		return time.Unix(int64(exp), 0), nil
	case json.Number:
		timestamp, _ := exp.Int64()
		return time.Unix(timestamp, 0), nil
	default:
		return time.Time{}, fmt.Errorf("failed to parse token experation")
	}
}
