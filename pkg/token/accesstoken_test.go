package token

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)



const (
	testSubID = "83c44b7b-2b02-4be8-8c70-c37e1cfb4ede"
	testTenantID = "1b4e67bf-39b2-4eb1-bec3-5099dd556b07"
)

var _ = Describe("Access Token Tests", func() {
	var (
		signingKey *rsa.PrivateKey
	)

	BeforeSuite(func(){
		var err error
		signingKey, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).ToNot(HaveOccurred())
	})

	Context("GetTokenTenantID", func() {
		It("Get Valid Tenant ID", func(){
			token, err := getTestToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			tenantID, err := token.GetTokenTenantId()
			Expect(err).ToNot(HaveOccurred())

			Expect(tenantID).To(Equal(testTenantID))
		})
	})

	Context("GetTokenExp", func() {
		It("", func(){
			expExpected := time.Now().Add(time.Hour).Unix()

			token, err := getTestToken(expExpected, signingKey)
			Expect(err).ToNot(HaveOccurred())

			expActual, err := token.GetTokenExp()
			Expect(err).ToNot(HaveOccurred())

			Expect(expExpected).To(Equal(expActual.Unix()))
		})
	})
})

func getTestToken(exp int64, signingKey *rsa.PrivateKey) (AccessToken, error){
	claims := jwt.MapClaims{
		"aud":    "test.azurecr.io",
		"exp":    exp,
		"grant_type": "refresh_token",
		"iat":    time.Now().AddDate(0, 0, -2).Unix(),
		"sub": testSubID,
		"version": 1.0,
		"tenant": testTenantID,
		"permissions": map[string]interface{} {
			"actions": []string{"read"},
		},
		"jti": "bb8d6d3d-c7b0-4f96-a390-8738f730e8c6",
		"iss":    "Azure Container Registry",
		"nbf":    time.Now().AddDate(0, 0, -1).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256,claims)
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}

	return AccessToken(tokenString), nil
}
