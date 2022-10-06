package authorizer

import (
	"context"

	"github.com/Azure/msi-acrpull/pkg/authorizer/types"
)

//go:generate sh -c "mockgen github.com/Azure/msi-acrpull/pkg/authorizer Interface,ManagedIdentityTokenRetriever,ACRTokenExchanger > ./mock_$GOPACKAGE/interfaces.go"

// Interface is the authorizer interface to acquire ACR access tokens.
type Interface interface {
	AcquireACRAccessTokenWithManagedIdentity(clientID string, identityResourceID string, acrFQDN string) (types.AccessToken, error)
	AcquireACRAccessTokenWithWorkloadIdentity(ctx context.Context, clientID string, tenantID string, acrFQDN string) (types.AccessToken, error)
}

// ACRTokenExchanger is the interface to exchange an ACR access token.
type ACRTokenExchanger interface {
	ExchangeACRAccessToken(armToken types.AccessToken, tenantID, acrFQDN string) (types.AccessToken, error)
}

// MIARMTokenRetriever is the interface to retrieve an ARM access token via managed identity.
type ManagedIdentityARMTokenRetriever interface {
	AcquireARMToken(clientID, resourceID string) (types.AccessToken, error)
}

// WIARMTokenRetriever is the interface to retrieve an ARM access token via workload identity.
type WorkloadIdentityARMTokenRetriever interface {
	AcquireARMToken(ctx context.Context, clientID, tenantID string) (types.AccessToken, error)
}
