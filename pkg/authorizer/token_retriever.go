package authorizer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Azure/msi-acrpull/pkg/authorizer/types"
)

const (
	defaultARMResource              = "https://management.azure.com/"
	customARMResourceEnvVar         = "ARM_RESOURCE"
	msiMetadataEndpoint             = "http://169.254.169.254/metadata/identity/oauth2/token"
	defaultCacheExpirationInSeconds = 600
)

// TokenRetriever is an instance of ManagedIdentityTokenRetriever
type TokenRetriever struct {
	metadataEndpoint string
	cache            sync.Map
	cacheExpiration  time.Duration
	client           *rateLimitedClient
}

type cachedToken struct {
	token    types.AccessToken
	notAfter time.Time
}

// NewTokenRetriever returns a new token retriever
func NewTokenRetriever() *TokenRetriever {
	return &TokenRetriever{
		metadataEndpoint: msiMetadataEndpoint,
		cache:            sync.Map{},
		cacheExpiration:  time.Duration(defaultCacheExpirationInSeconds) * time.Second,
		client:           newRateLimitedClient(),
	}
}

// AcquireARMToken acquires the managed identity ARM access token
func (tr *TokenRetriever) AcquireARMToken(ctx context.Context, clientID string, resourceID string) (types.AccessToken, error) {
	cacheKey := strings.ToLower(clientID)
	if cacheKey == "" {
		cacheKey = strings.ToLower(resourceID)
	}

	cached, ok := tr.cache.Load(cacheKey)
	if ok {
		token := cached.(cachedToken)
		if time.Now().UTC().Sub(token.notAfter) < 0 {
			return token.token, nil
		}

		tr.cache.Delete(cacheKey)
	}

	token, err := tr.refreshToken(ctx, clientID, resourceID)
	if err != nil {
		return "", fmt.Errorf("failed to refresh ARM access token: %w", err)
	}

	tr.cache.Store(cacheKey, cachedToken{token: token, notAfter: time.Now().UTC().Add(tr.cacheExpiration)})
	return token, nil
}

func (tr *TokenRetriever) refreshToken(ctx context.Context, clientID, resourceID string) (types.AccessToken, error) {
	msiEndpoint, err := url.Parse(tr.metadataEndpoint)
	if err != nil {
		return "", err
	}

	parameters := url.Values{}
	if clientID != "" {
		parameters.Add("client_id", clientID)
	} else {
		parameters.Add("mi_res_id", resourceID)
	}

	customARMResource := os.Getenv(customARMResourceEnvVar)
	if customARMResource == "" {
		parameters.Add("resource", defaultARMResource)
	} else {
		parameters.Add("resource", customARMResource)
	}

	parameters.Add("api-version", "2018-02-01")

	msiEndpoint.RawQuery = parameters.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", msiEndpoint.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Metadata", "true")

	var resp *http.Response
	defer func() {
		if resp != nil && resp.Body != nil {
			if err := resp.Body.Close(); err != nil {
				fmt.Printf("failed to close response body: %v\n", err)
			}
		}
	}()

	resp, err = tr.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send metadata endpoint request: %w", err)
	}

	if resp.StatusCode != 200 {
		responseBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Metadata endpoint returned error status: %d. body: %s", resp.StatusCode, string(responseBytes))
	}

	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read metadata endpoint response: %w", err)
	}

	var tokenResp tokenResponse
	err = json.Unmarshal(responseBytes, &tokenResp)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal metadata endpoint response: %w", err)
	}

	return types.AccessToken(tokenResp.AccessToken), nil
}
