package authorizer

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/Azure/msi-acrpull/pkg/authorizer/types"
	"github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestAuthorizer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Authorizer Test Suite")
}

const (
	testTenantID   = "1b4e67bf-39b2-4eb1-bec3-5099dd556b07"
	testClientID   = "a24051cb-67a7-4aa9-8abe-0765312b658a"
	testResourceID = "/subscriptions/11b8b9f9-1812-4828-9cb5-b41ee15d63c7/resourceGroups/test-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/test-mi"
	testACR        = "testcr.azurecr.io"
)

var signingKey *rsa.PrivateKey

var _ = BeforeSuite(func() {
	var err error
	signingKey, err = rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).ToNot(HaveOccurred())
})

func getTestArmToken(exp int64, signingKey *rsa.PrivateKey) (types.AccessToken, error) {
	claims := jwt.MapClaims{
		"aud":        "https://management.azure.com/",
		"exp":        exp,
		"grant_type": "refresh_token",
		"iat":        time.Now().AddDate(0, 0, -2).Unix(),
		"sub":        "sub",
		"ver":        1.0,
		"tid":        testTenantID,
		"xms_mirid":  "fake/msi/resource/id",
		"jti":        "bb8d6d3d-c7b0-4f96-a390-8738f730e8c6",
		"iss":        "https://sts.windows.net/" + testTenantID + "/",
		"nbf":        time.Now().AddDate(0, 0, -1).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}

	return types.AccessToken(tokenString), nil
}

func getTestAcrToken(exp int64, signingKey *rsa.PrivateKey) (types.AccessToken, error) {
	claims := jwt.MapClaims{
		"aud":        "test.azurecr.io",
		"exp":        exp,
		"grant_type": "refresh_token",
		"iat":        time.Now().AddDate(0, 0, -2).Unix(),
		"sub":        "sub",
		"version":    1.0,
		"tenant":     testTenantID,
		"permissions": map[string]interface{}{
			"actions": []string{"read"},
		},
		"jti": "bb8d6d3d-c7b0-4f96-a390-8738f730e8c6",
		"iss": "Azure Container Registry",
		"nbf": time.Now().AddDate(0, 0, -1).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}

	return types.AccessToken(tokenString), nil
}
