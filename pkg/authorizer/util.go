package authorizer

import (
	"encoding/base64"
	"fmt"

	"github.com/Azure/msi-acrpull/pkg/authorizer/types"
)

const (
	acrUsername = "00000000-0000-0000-0000-000000000000"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

// CreateACRDockerCfg creates an ACR docker config using given access token.
func CreateACRDockerCfg(acrFQDN string, accessToken types.AccessToken) string {
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", acrUsername, accessToken)))
	dockercfg := fmt.Sprintf("{\"auths\":{\"%s\":{\"username\":\"%s\",\"password\":\"%s\",\"email\":\"msi-acrpull@azurecr.io\",\"auth\":\"%s\"}}}",
		acrFQDN, acrUsername, accessToken, auth)

	return dockercfg
}
