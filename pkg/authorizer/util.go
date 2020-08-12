package authorizer

import (
	"encoding/base64"
	"fmt"
)

const (
	acrUsername = "00000000-0000-0000-0000-000000000000"
)

// CreateACRDockerCfg creates an ACR docker config using given access token.
func CreateACRDockerCfg(acrFQDN string, accessToken AccessToken) string {
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", acrUsername, accessToken)))
	dockercfg := fmt.Sprintf("{\"auths\":{\"%s\":{\"username\":\"%s\",\"password\":\"%s\",\"email\":\"msi-acrpull@azurecr.io\",\"auth\":\"%s\"}}}",
		acrFQDN, acrUsername, accessToken, auth)

	return dockercfg
}
