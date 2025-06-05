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

// AcquireACRAccessToken acquires ACR access token using managed identity resource or client ID.
func (az *Authorizer) AcquireACRAccessToken(ctx context.Context, identityResourceID, clientID, acrFQDN, scope string) (azcore.AccessToken, error) {
	var id azidentity.ManagedIDKind
	if clientID != "" {
		id = azidentity.ClientID(clientID)
	} else if identityResourceID != "" {
		id = azidentity.ResourceID(identityResourceID)
	} else {
		return azcore.AccessToken{}, fmt.Errorf("either a client ID or a resource ID is required")
	}
	acrAudienceEntraToken, err := AcquireACRAudienceEntraToken(ctx, id)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to get ACR audience Entra token: %w", err)
	}

	return ExchangeACRAccessToken(ctx, acrAudienceEntraToken, acrFQDN, scope)
}
