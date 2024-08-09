package authorizer

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// Authorizer is an instance of authorizer
type Authorizer struct{}

// NewAuthorizer returns an authorizer
func NewAuthorizer() *Authorizer {
	return &Authorizer{}
}

// AcquireACRAccessTokenWithResourceID acquires ACR access token using managed identity resource ID (/subscriptions/{id}/resourceGroups/{group}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{name}).
func (az *Authorizer) AcquireACRAccessTokenWithResourceID(ctx context.Context, identityResourceID string, acrFQDN string) (azcore.AccessToken, error) {
	armToken, err := AcquireARMToken(ctx, azidentity.ResourceID(identityResourceID))
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to get ARM access token: %w", err)
	}

	return ExchangeACRAccessToken(ctx, armToken, acrFQDN)
}

// AcquireACRAccessTokenWithClientID acquires ACR access token using managed identity client ID.
func (az *Authorizer) AcquireACRAccessTokenWithClientID(ctx context.Context, clientID string, acrFQDN string) (azcore.AccessToken, error) {
	armToken, err := AcquireARMToken(ctx, azidentity.ClientID(clientID))
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to get ARM access token: %w", err)
	}

	return ExchangeACRAccessToken(ctx, armToken, acrFQDN)
}
