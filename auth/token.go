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

	"github.com/dgrijalva/jwt-go"
)

const (
	armResource = "https://management.azure.com/"
	endpoint    = "http://169.254.169.254/metadata/identity/oauth2/token"
)

type responseJSON struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

func acquireAuthTokenMSI(clientID string) (string, error) {
	msiendpoint, _ := url.Parse(endpoint)

	parameters := url.Values{}
	parameters.Add("resource", armResource)
	parameters.Add("client_id", clientID)
	parameters.Add("api-version", "2018-02-01")

	msiendpoint.RawQuery = parameters.Encode()

	req, err := http.NewRequest("GET", msiendpoint.String(), nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("Metadata", "true")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send metadata endpoint request: %s", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		responseBytes, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("Metadata endpoint returned error status: %d. body: %s", resp.StatusCode, string(responseBytes))
	}

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read metadata endpoint response: %s", err)
	}

	fmt.Println(string(responseBytes))

	var r responseJSON
	err = json.Unmarshal(responseBytes, &r)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal metadata endpoint response: %s", err)
	}

	return r.AccessToken, nil
}

func getTokenTenantId(token string) (string, error) {
	p := &jwt.Parser{SkipClaimsValidation: true}

	t, _, err := p.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse token")
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("unexpected claim type from token")
	}

	return claims["tid"].(string), nil
}

func acquireACRAccessToken(clientID string, acrFQDN string) (string, error) {
	var armtoken string
	var err error
	if armtoken, err = acquireAuthTokenMSI(clientID); err != nil {
		return "", fmt.Errorf("failed to get ARM access token: %s", err)
	}

	tid, err := getTokenTenantId(armtoken)
	if err != nil {
		return "", fmt.Errorf("failed to get tenant id from ARM token: %s", err)
	}

	eul := fmt.Sprintf("https://%s/oauth2/exchange", acrFQDN)
	parameters := url.Values{}
	parameters.Add("grant_type", "access_token")
	parameters.Add("service", acrFQDN)
	parameters.Add("tenant", tid)
	parameters.Add("access_token", armtoken)

	req, err := http.NewRequest("POST", eul, strings.NewReader(parameters.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to construct token exchange reqeust: %s", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(parameters.Encode())))

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send token exchange request: %s", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		responseBytes, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("ACR token exchange endpoint returned error status: %d. body: %s", resp.StatusCode, string(responseBytes))
	}

	responseBytes, err := ioutil.ReadAll(resp.Body)

	var r responseJSON
	err = json.Unmarshal(responseBytes, &r)
	if err != nil {
		return "", fmt.Errorf("failed to read token exchange response: %s. response: %s", err, string(responseBytes))
	}

	return r.RefreshToken, nil
}

func AcquireACRDockerCfg(clientID, acrFQDN string) (string, error) {
	accessToken, err := acquireACRAccessToken(clientID, acrFQDN)
	if err != nil {
		return "", fmt.Errorf("failed to get ACR access token: %s", err)
	}

	acrUsername := "00000000-0000-0000-0000-000000000000"
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", acrUsername, accessToken)))
	dockercfg := fmt.Sprintf("{\"auths\":{\"%s\":{\"username\":\"%s\",\"password\":\"%s\",\"email\":\"tokenman@azurecr.io\",\"auth\":\"%s\"}}}", acrFQDN, acrUsername, accessToken, auth)

	fmt.Println(dockercfg)

	return dockercfg, nil
}
