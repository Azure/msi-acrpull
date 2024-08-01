package types

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AccessToken string

func (t AccessToken) GetTokenClaims() (jwt.MapClaims, error) {
	p := &jwt.Parser{}
	skipValidations := jwt.WithoutClaimsValidation()
	skipValidations(p)

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
		return time.Unix(int64(exp), 0).UTC(), nil
	case json.Number:
		timestamp, _ := exp.Int64()
		return time.Unix(timestamp, 0).UTC(), nil
	default:
		return time.Time{}, fmt.Errorf("failed to parse token experation")
	}
}
