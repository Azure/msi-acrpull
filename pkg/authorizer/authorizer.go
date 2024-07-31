package authorizer

import (
	"context"
	"fmt"

	"github.com/Azure/msi-acrpull/pkg/authorizer/types"
	"github.com/go-logr/logr"
)

// Authorizer is an instance of authorizer
type Authorizer struct {
	tokenRetriever ManagedIdentityTokenRetriever
	tokenExchanger ACRTokenExchanger
}

// NewAuthorizer returns an authorizer
func NewAuthorizer() *Authorizer {
	return &Authorizer{
		tokenRetriever: NewTokenRetriever(),
		tokenExchanger: NewTokenExchanger(),
	}
}

// AcquireACRAccessTokenWithResourceID acquires ACR access token using managed identity resource ID (/subscriptions/{id}/resourceGroups/{group}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{name}).
func (az *Authorizer) AcquireACRAccessTokenWithResourceID(ctx context.Context, log logr.Logger, identityResourceID string, acrFQDN string) (types.AccessToken, error) {
	armToken, err := az.tokenRetriever.AcquireARMToken(ctx, log, "", identityResourceID)
	if err != nil {
		return "", fmt.Errorf("failed to get ARM access token: %w", err)
	}

	return az.tokenExchanger.ExchangeACRAccessToken(ctx, log, armToken, acrFQDN)
}

// AcquireACRAccessTokenWithClientID acquires ACR access token using managed identity client ID.
func (az *Authorizer) AcquireACRAccessTokenWithClientID(ctx context.Context, log logr.Logger, clientID string, acrFQDN string) (types.AccessToken, error) {
	armToken, err := az.tokenRetriever.AcquireARMToken(ctx, log, clientID, "")
	if err != nil {
		return "", fmt.Errorf("failed to get ARM access token: %w", err)
	}

	return az.tokenExchanger.ExchangeACRAccessToken(ctx, log, armToken, acrFQDN)
}
