package authorizer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

const (
	acrUsername = "00000000-0000-0000-0000-000000000000"
)

type dockercfg struct {
	Auths map[string]auth `json:"auths"`
}

type auth struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Auth     string `json:"auth"`
}

// CreateACRDockerCfg creates an ACR docker config using given access token.
func CreateACRDockerCfg(acrFQDN string, accessToken azcore.AccessToken) (string, error) {
	cfg := dockercfg{
		Auths: map[string]auth{
			acrFQDN: {
				Username: acrUsername,
				Password: accessToken.Token,
				Email:    "msi-acrpull@azurecr.io",
				Auth:     base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", acrUsername, accessToken.Token))),
			},
		},
	}

	encoded, err := json.Marshal(cfg)
	return string(encoded), err
}
