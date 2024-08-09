package authorizer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
	"k8s.io/utils/ptr"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/containers/azcontainerregistry"
)

// ExchangeACRAccessToken exchanges an ARM access token to an ACR access token
func ExchangeACRAccessToken(ctx context.Context, armToken azcore.AccessToken, acrFQDN string) (azcore.AccessToken, error) {
	endpoint, err := url.Parse(fmt.Sprintf("https://%s", acrFQDN))
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to parse ACR endpoint: %w", err)
	}

	// TODO: cache refresh token? need to determine how often we'd actually be able to re-use it
	client, err := azcontainerregistry.NewAuthenticationClient(endpoint.String(), nil)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to create ACR authentication client: %w", err)
	}
	refreshResponse, err := client.ExchangeAADAccessTokenForACRRefreshToken(ctx, "refresh_token", endpoint.Hostname(), &azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenOptions{
		AccessToken: ptr.To(armToken.Token),
	})
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to exchange AAD access token for ACR refresh token: %w", err)
	}

	if refreshResponse.RefreshToken == nil {
		return azcore.AccessToken{}, errors.New("got an empty response when exchanging AAD access token for ACR refresh token")
	}

	// TODO: how to get scope to pull across whole registry? `registry:...` scopes are only documented for admin
	accessResponse, err := client.ExchangeACRRefreshTokenForACRAccessToken(ctx, acrFQDN, "repository:*:pull", *refreshResponse.RefreshToken, &azcontainerregistry.AuthenticationClientExchangeACRRefreshTokenForACRAccessTokenOptions{
		GrantType: ptr.To(azcontainerregistry.TokenGrantTypeRefreshToken),
	})
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to exchange ACR refresh token for ACR access token: %w", err)
	}
	if accessResponse.AccessToken == nil {
		return azcore.AccessToken{}, errors.New("got an empty response when exchanging ACR refresh token for ACR access token")
	}

	token, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(*accessResponse.AccessToken, jwt.MapClaims{})
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to parse ACR access token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return azcore.AccessToken{}, fmt.Errorf("unexpected claim type from ACR access token")
	}

	var expiry time.Time
	switch exp := claims["exp"].(type) {
	case float64:
		expiry = time.Unix(int64(exp), 0)
	case json.Number:
		timestamp, _ := exp.Int64()
		expiry = time.Unix(timestamp, 0)
	default:
		return azcore.AccessToken{}, fmt.Errorf("failed to parse ACR acess token expiration")
	}

	return azcore.AccessToken{
		Token:     *accessResponse.AccessToken,
		ExpiresOn: expiry,
	}, nil
}
