package authorizer

import (
	"context"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	msiacrpullv1beta2 "github.com/Azure/msi-acrpull/api/v1beta2"
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

func ARMTokenForBinding(ctx context.Context, spec msiacrpullv1beta2.AcrPullBindingSpec, tenantId, clientId, serviceAccountToken string) (azcore.AccessToken, error) {
	env := environment(spec.ACR.Environment)

	var credential azcore.TokenCredential
	var err error
	switch {
	case spec.Auth.ManagedIdentity != nil:
		var id azidentity.ManagedIDKind
		if spec.Auth.ManagedIdentity.ClientID != "" {
			id = azidentity.ClientID(spec.Auth.ManagedIdentity.ClientID)
		} else if spec.Auth.ManagedIdentity.ResourceID != "" {
			id = azidentity.ResourceID(spec.Auth.ManagedIdentity.ResourceID)
		}
		credential, err = azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{ID: id})
	case spec.Auth.WorkloadIdentity != nil:
		// n.b. the built-in azidentity.WorkloadIdentityCredential assumes we're loading a service account token
		// from a file in a Pod, where the Kubernetes API server is rotating it, etc. Unfortunately that is not
		// our use-case here, and we certainly don't want to centralize every service account token we ever mint
		// in the filesystem of this controller, so we can use the lower-level client assertion credential instead.
		credential, err = azidentity.NewClientAssertionCredential(tenantId, clientId, func(ctx context.Context) (string, error) {
			return serviceAccountToken, nil
		}, &azidentity.ClientAssertionCredentialOptions{
			ClientOptions: azcore.ClientOptions{
				Cloud: cloud.Configuration{
					ActiveDirectoryAuthorityHost: env.ActiveDirectoryAuthorityHost,
				},
			},
			DisableInstanceDiscovery: true,
		})
	}
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to build credential: %w", err)
	}
	if credential == nil {
		// this should never happen with the validation we have on the CRD
		panic(fmt.Errorf("programmer error: ACRPullBinding.Spec.Auth has no method: %#v", spec.Auth))
	}
	return credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{env.Services[cloud.ResourceManager].Audience + "/.default"}})
}

func environment(input msiacrpullv1beta2.AzureEnvironmentType) cloud.Configuration {
	switch input {
	case msiacrpullv1beta2.AzureEnvironmentPublicCloud:
		return cloud.AzurePublic
	case msiacrpullv1beta2.AzureEnvironmentUSGovernmentCloud:
		return cloud.AzureGovernment
	case msiacrpullv1beta2.AzureEnvironmentChinaCloud:
		return cloud.AzureChina
	default:
		panic(fmt.Errorf("unsupported msiacrpullv1beta2.AzureEnvironmentType: %s", input))
	}
}
