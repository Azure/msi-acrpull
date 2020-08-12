package types

import (
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	testTenantID = "1b4e67bf-39b2-4eb1-bec3-5099dd556b07"
)

var _ = Describe("Access Token Tests", func() {
	var (
		signingKey *rsa.PrivateKey
	)

	BeforeSuite(func() {
		var err error
		signingKey, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).ToNot(HaveOccurred())
	})

	Context("GetTokenTenantID", func() {
		It("Get Valid Tenant ID Arm Token", func() {
			token, err := getTestArmToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			tenantID, err := token.GetTokenTenantId()
			Expect(err).ToNot(HaveOccurred())

			Expect(tenantID).To(Equal(testTenantID))
		})

		It("Get Valid Tenant ID ACR Token", func() {
			token, err := getTestAcrToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			tenantID, err := token.GetTokenTenantId()
			Expect(err).ToNot(HaveOccurred())

			Expect(tenantID).To(Equal(testTenantID))
		})
	})

	Context("GetTokenExp", func() {
		It("Retrieves Correct Exp Time from ARM Token", func() {
			expExpected := time.Now().Add(time.Hour).Unix()

			token, err := getTestArmToken(expExpected, signingKey)
			Expect(err).ToNot(HaveOccurred())

			expActual, err := token.GetTokenExp()
			Expect(err).ToNot(HaveOccurred())
			Expect(expExpected).To(Equal(expActual.Unix()))
		})

		It("Retrieves Correct Exp Time from ACR Token", func() {
			expExpected := time.Now().Add(time.Hour).Unix()

			token, err := getTestAcrToken(expExpected, signingKey)
			Expect(err).ToNot(HaveOccurred())

			expActual, err := token.GetTokenExp()
			Expect(err).ToNot(HaveOccurred())
			Expect(expExpected).To(Equal(expActual.Unix()))
		})
	})
})

func getTestArmToken(exp int64, signingKey *rsa.PrivateKey) (AccessToken, error) {
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

	return AccessToken(tokenString), nil
}

func getTestAcrToken(exp int64, signingKey *rsa.PrivateKey) (AccessToken, error) {
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

	return AccessToken(tokenString), nil
}
