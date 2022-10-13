package authorizer

import (
	"context"
	"fmt"

	"github.com/Azure/msi-acrpull/pkg/authorizer/types"
)

// Authorizer is an instance of authorizer
type Authorizer struct {
	managedIdentityTokenRetriever  ManagedIdentityARMTokenRetriever
	workloadIdentityTokenRetriever WorkloadIdentityARMTokenRetriever
	tokenExchanger                 ACRTokenExchanger
}

// NewAuthorizer returns an authorizer
func NewAuthorizer() *Authorizer {
	return &Authorizer{
		managedIdentityTokenRetriever:  NewManagedIdentityTokenRetriever(),
		workloadIdentityTokenRetriever: NewWorkloadIdentityTokenRetriever(),
		tokenExchanger:                 NewTokenExchanger(),
	}
}

func (az *Authorizer) AcquireACRAccessTokenWithManagedIdentity(clientID string, identityResourceID string, acrFQDN string) (types.AccessToken, error) {
	var armToken types.AccessToken
	var err error

	if clientID != "" {
		armToken, err = az.managedIdentityTokenRetriever.AcquireARMToken(clientID, "")
	} else {
		armToken, err = az.managedIdentityTokenRetriever.AcquireARMToken("", identityResourceID)
	}

	if err != nil {
		return "", fmt.Errorf("failed to get ARM access token: %w", err)
	}

	tenantID, err := getTokenTenantId(armToken)
	if err != nil {
		return "", fmt.Errorf("failed to get tenant ID: %w", err)
	}

	return az.tokenExchanger.ExchangeACRAccessToken(armToken, tenantID, acrFQDN)
}

func (az *Authorizer) AcquireACRAccessTokenWithWorkloadIdentity(ctx context.Context, clientID string, tenantID string, acrFQDN string) (types.AccessToken, error) {
	armToken, err := az.workloadIdentityTokenRetriever.AcquireARMToken(ctx, clientID, tenantID)
	if err != nil {
		return "", fmt.Errorf("failed to get ARM access token: %w", err)
	}

	return az.tokenExchanger.ExchangeACRAccessToken(armToken, tenantID, acrFQDN)
}

func getTokenTenantId(t types.AccessToken) (string, error) {
	claims, err := t.GetTokenClaims()
	if err != nil {
		return "", err
	}
	tenantID, ok := claims["tid"].(string)
	if ok {
		return tenantID, nil
	}

	tenantID, ok = claims["tenant"].(string)
	if ok {
		return tenantID, nil
	}

	return "", fmt.Errorf("token has no tenant ID")
}
