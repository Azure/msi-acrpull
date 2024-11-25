package authorizer

import (
	"context"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

const (
	defaultARMResource      = "https://management.azure.com/"
	customARMResourceEnvVar = "ARM_RESOURCE"
)

func AcquireARMToken(ctx context.Context, id azidentity.ManagedIDKind) (azcore.AccessToken, error) {
	customARMResource := os.Getenv(customARMResourceEnvVar)
	if customARMResource == "" {
		customARMResource = defaultARMResource
	}

	cred, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{ID: id})
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to build managed identity credential: %w", err)
	}
	return cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{customARMResource}})
}
