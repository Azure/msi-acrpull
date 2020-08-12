package authorizer

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/Azure/msi-acrpull/pkg/authorizer/mock_authorizer"
	"github.com/Azure/msi-acrpull/pkg/authorizer/types"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	testTenantID   = "1b4e67bf-39b2-4eb1-bec3-5099dd556b07"
	testClientID   = "a24051cb-67a7-4aa9-8abe-0765312b658a"
	testResourceID = "/subscriptions/11b8b9f9-1812-4828-9cb5-b41ee15d63c7/resourceGroups/test-rg/providers/Microsoft.ManagedIdentities/managedIdentities/test-mi"
	testACR        = "testcr.azurecr.io"
)

var _ = Describe("Authorizer Tests", func() {
	var (
		signingKey *rsa.PrivateKey
		mockCtrl   *gomock.Controller
	)

	BeforeSuite(func() {
		mockCtrl = gomock.NewController(GinkgoT())

		var err error
		signingKey, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).ToNot(HaveOccurred())
	})

	Context("Acquire ACR Access Token With ResourceID", func() {
		It("Get ACR Token with Resource ID Successfully", func() {
			armToken, err := getTestArmToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			acrToken, err := getTestAcrToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			tr := mock_authorizer.NewMockManagedIdentityTokenRetriever(mockCtrl)
			te := mock_authorizer.NewMockACRTokenExchanger(mockCtrl)

			az := &Authorizer{
				tokenRetriever: tr,
				tokenExchanger: te,
			}

			tr.EXPECT().AcquireARMToken("", testResourceID).Return(armToken, nil).Times(1)
			te.EXPECT().ExchangeACRAccessToken(armToken, testACR).Return(acrToken, nil).Times(1)

			t, err := az.AcquireACRAccessTokenWithResourceID(testResourceID, testACR)
			Expect(err).To(BeNil())
			Expect(t).NotTo(BeNil())
			Expect(t).To(Equal(acrToken))
		})

		It("Get ACR Token with Client ID Successfully", func() {
			armToken, err := getTestArmToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			acrToken, err := getTestAcrToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			tr := mock_authorizer.NewMockManagedIdentityTokenRetriever(mockCtrl)
			te := mock_authorizer.NewMockACRTokenExchanger(mockCtrl)

			az := &Authorizer{
				tokenRetriever: tr,
				tokenExchanger: te,
			}

			tr.EXPECT().AcquireARMToken(testClientID, "").Return(armToken, nil).Times(1)
			te.EXPECT().ExchangeACRAccessToken(armToken, testACR).Return(acrToken, nil).Times(1)

			t, err := az.AcquireACRAccessTokenWithClientID(testClientID, testACR)
			Expect(err).To(BeNil())
			Expect(t).NotTo(BeNil())
			Expect(t).To(Equal(acrToken))
		})

		It("Returns Error when ARM Token Retrieve Failed", func() {
			tr := mock_authorizer.NewMockManagedIdentityTokenRetriever(mockCtrl)
			te := mock_authorizer.NewMockACRTokenExchanger(mockCtrl)

			az := &Authorizer{
				tokenRetriever: tr,
				tokenExchanger: te,
			}

			tr.EXPECT().AcquireARMToken(testClientID, "").Return(types.AccessToken(""), errors.New("test error")).Times(1)

			t, err := az.AcquireACRAccessTokenWithClientID(testClientID, testACR)
			Expect(string(t)).To(Equal(""))
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("test error"))
		})
	})
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
