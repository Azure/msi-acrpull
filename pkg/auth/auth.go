package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	armResource           = "https://management.azure.com/"
	msiMetadataEndpoint   = "http://169.254.169.254/metadata/identity/oauth2/token"
	acrUsername           = "00000000-0000-0000-0000-000000000000"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

func AcquireACRAccessToken(clientID string, acrFQDN string) (AccessToken, error) {
	armToken, err := acquireArmToken(clientID)
	if err != nil {
		return "", fmt.Errorf("failed to get ARM access token: %w", err)
	}

	tenantID, err := armToken.GetTokenTenantId()
	if err != nil {
		return "", fmt.Errorf("failed to get tenant id from ARM token: %w", err)
	}

	exchangeURL := fmt.Sprintf("https://%s/oauth2/exchange", acrFQDN)
	parameters := url.Values{}
	parameters.Add("grant_type", "access_token")
	parameters.Add("service", acrFQDN)
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
		return "", fmt.Errorf("ACR token exchange msiMetadataEndpoint returned error status: %d. body: %s", resp.StatusCode, string(responseBytes))
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

	return AccessToken(tokenResp.RefreshToken), nil
}

func CreateACRDockerCfg(acrFQDN string, accessToken AccessToken) (string, error) {
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", acrUsername, accessToken)))
	dockercfg := fmt.Sprintf("{\"auths\":{\"%s\":{\"username\":\"%s\",\"password\":\"%s\",\"email\":\"tokenman@azurecr.io\",\"auth\":\"%s\"}}}",
		acrFQDN, acrUsername, accessToken, auth)

	return dockercfg, nil
}

func acquireArmToken(clientID string) (AccessToken, error) {
	msiEndpoint, err := url.Parse(msiMetadataEndpoint)
	if err != nil {
		return "", err
	}

	parameters := url.Values{}
	parameters.Add("resource", armResource)
	parameters.Add("client_id", clientID)
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

	return AccessToken(tokenResp.AccessToken), nil
}

func closeResponse(resp *http.Response) {
	if resp == nil {
		return
	}
	resp.Body.Close()
}
