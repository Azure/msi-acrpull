package authorizer

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

//go:generate sh -c "$MOCKGEN github.com/Azure/msi-acrpull/pkg/authorizer Interface,ManagedIdentityTokenRetriever,ACRTokenExchanger > ./mock_$GOPACKAGE/interfaces.go"

// Interface is the authorizer interface to acquire ACR access tokens.
type Interface interface {
	AcquireACRAccessToken(ctx context.Context, identityResourceID, clientID, acrFQDN, scope string) (azcore.AccessToken, error)
}
