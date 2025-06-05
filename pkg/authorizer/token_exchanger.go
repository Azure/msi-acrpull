package authorizer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	msiacrpullv1beta2 "github.com/Azure/msi-acrpull/api/v1beta2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
	"k8s.io/utils/ptr"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/containers/azcontainerregistry"
)

// ExchangeACRAccessToken exchanges an ACR audience Entra token to an actual ACR access token
func ExchangeACRAccessToken(ctx context.Context, acrAudienceEntraToken azcore.AccessToken, acrFQDN, scope string) (azcore.AccessToken, error) {
	endpoint, err := url.Parse(fmt.Sprintf("https://%s", acrFQDN))
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to parse ACR endpoint: %w", err)
	}

	client, err := azcontainerregistry.NewAuthenticationClient(endpoint.String(), nil)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to create ACR authentication client: %w", err)
	}
	refreshResponse, err := client.ExchangeAADAccessTokenForACRRefreshToken(ctx, azcontainerregistry.PostContentSchemaGrantTypeAccessToken, endpoint.Hostname(), &azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenOptions{
		AccessToken: ptr.To(acrAudienceEntraToken.Token),
	})
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to exchange AAD access token for ACR refresh token: %w", err)
	}

	if refreshResponse.RefreshToken == nil {
		return azcore.AccessToken{}, errors.New("got an empty response when exchanging AAD access token for ACR refresh token")
	}

	// for legacy compatibility, we allow exposing the unscoped refresh token
	accessToken := *refreshResponse.RefreshToken
	if scope != "" {
		accessResponse, err := client.ExchangeACRRefreshTokenForACRAccessToken(ctx, acrFQDN, scope, *refreshResponse.RefreshToken, &azcontainerregistry.AuthenticationClientExchangeACRRefreshTokenForACRAccessTokenOptions{
			GrantType: ptr.To(azcontainerregistry.TokenGrantTypeRefreshToken),
		})
		if err != nil {
			return azcore.AccessToken{}, fmt.Errorf("failed to exchange ACR refresh token for ACR access token: %w", err)
		}
		if accessResponse.AccessToken == nil {
			return azcore.AccessToken{}, errors.New("got an empty response when exchanging ACR refresh token for ACR access token")
		}
		accessToken = *accessResponse.AccessToken
	}

	token, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(accessToken, jwt.MapClaims{})
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
		Token:     accessToken,
		ExpiresOn: expiry,
	}, nil
}

func ExchangeACRAccessTokenForSpec(ctx context.Context, acrAudienceEntraToken azcore.AccessToken, spec msiacrpullv1beta2.AcrConfiguration) (azcore.AccessToken, error) {
	return ExchangeACRAccessToken(ctx, acrAudienceEntraToken, spec.Server, spec.Scope)
}
