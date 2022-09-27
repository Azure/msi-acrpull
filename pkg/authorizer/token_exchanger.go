package authorizer

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Azure/msi-acrpull/pkg/authorizer/types"
)

// TokenExchanger is an instance of ACRTokenExchanger
type TokenExchanger struct {
	acrServerScheme string
}

// NewTokenExchanger returns a new token exchanger
func NewTokenExchanger() *TokenExchanger {
	return &TokenExchanger{
		acrServerScheme: "https",
	}
}

// ExchangeACRAccessToken exchanges an ARM access token to an ACR access token
func (te *TokenExchanger) ExchangeACRAccessToken(armToken types.AccessToken, tenantID, acrFQDN string) (types.AccessToken, error) {
	scheme := te.acrServerScheme
	if scheme == "" {
		scheme = "https"
	}

	exchangeURL := fmt.Sprintf("%s://%s/oauth2/exchange", scheme, acrFQDN)
	ul, err := url.Parse(exchangeURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse token exchange url: %w", err)
	}
	parameters := url.Values{}
	parameters.Add("grant_type", "access_token")
	parameters.Add("service", ul.Hostname())
	parameters.Add("tenant", tenantID)
	parameters.Add("access_token", string(armToken))

	req, err := http.NewRequest("POST", exchangeURL, strings.NewReader(parameters.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to construct token exchange reqeust: %w", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(parameters.Encode())))

	client := &http.Client{}
	var resp *http.Response
	defer closeResponse(resp)

	resp, err = client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send token exchange request: %w", err)
	}

	if resp.StatusCode != 200 {
		responseBytes, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("ACR token exchange endpoint returned error status: %d. body: %s", resp.StatusCode, string(responseBytes))
	}

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read request body: %w", err)
	}

	var tokenResp tokenResponse
	err = json.Unmarshal(responseBytes, &tokenResp)
	if err != nil {
		return "", fmt.Errorf("failed to read token exchange response: %w. response: %s", err, string(responseBytes))
	}

	return types.AccessToken(tokenResp.RefreshToken), nil
}
