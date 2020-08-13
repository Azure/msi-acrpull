package authorizer

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Azure/msi-acrpull/pkg/authorizer/types"
)

const (
	armResource                     = "https://management.azure.com/"
	msiMetadataEndpoint             = "http://169.254.169.254/metadata/identity/oauth2/token"
	defaultCacheExpirationInSeconds = 600
)

// TokenRetriever is an instance of ManagedIdentityTokenRetriever
type TokenRetriever struct {
	metadataEndpoint string
	cache            sync.Map
	cacheExpiration  time.Duration
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
	}
}

// AcquireARMToken acquires the managed identity ARM access token
func (tr *TokenRetriever) AcquireARMToken(clientID string, resourceID string) (types.AccessToken, error) {
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

	token, err := tr.refreshToken(clientID, resourceID)
	if err != nil {
		return "", fmt.Errorf("failed to refresh ARM access token: %w", err)
	}

	tr.cache.Store(cacheKey, cachedToken{token: token, notAfter: time.Now().UTC().Add(tr.cacheExpiration)})
	return token, nil
}

func (tr *TokenRetriever) refreshToken(clientID, resourceID string) (types.AccessToken, error) {
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

	parameters.Add("resource", armResource)
	parameters.Add("api-version", "2018-02-01")

	msiEndpoint.RawQuery = parameters.Encode()

	req, err := http.NewRequest("GET", msiEndpoint.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Metadata", "true")

	client := &http.Client{}
	var resp *http.Response
	defer closeResponse(resp)

	resp, err = client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send metadata endpoint request: %w", err)
	}

	if resp.StatusCode != 200 {
		responseBytes, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("Metadata endpoint returned error status: %d. body: %s", resp.StatusCode, string(responseBytes))
	}

	responseBytes, err := ioutil.ReadAll(resp.Body)
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

func closeResponse(resp *http.Response) {
	if resp == nil {
		return
	}
	resp.Body.Close()
}
