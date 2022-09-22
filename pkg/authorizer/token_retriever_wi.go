package authorizer

import (
	"context"
	"fmt"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// Get auth token from service account token
func AcquireARMTokenFromServiceAccountToken(ctx context.Context, tenantID, clientID string) (types.AccessToken, error) {

	const (
		authorityHost = "https://login.microsoftonline.com/"
		resource      = "https://management.azure.com/.default"
	)

	cred := confidential.NewCredFromAssertionCallback(func(context.Context, confidential.AssertionRequestOptions) (string, error) {
		return readJWTFromFS()
	})

	confidentialClientApp, err := confidential.New(
		clientID,
		cred,
		confidential.WithAuthority(fmt.Sprintf("%s%s/oauth2/token", authorityHost, tenantID)))
	if err != nil {
		return "", fmt.Errorf("Unable to get new confidential client app: %w", err)
	}

	authResult, err := confidentialClientApp.AcquireTokenByCredential(ctx, []string{"/.default"})
	if err != nil {
		return "", fmt.Errorf("Unable to acquire bearer token: %w", err)
	}

	return authResult.AccessToken, nil
}

func readJWTFromFS() (string, error) {
	const SATokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	f, err := os.ReadFile(SATokenPath)
	if err != nil {
		return "", err
	}

	return string(f), nil
}
