package authorizer

import (
	"context"
	"errors"
	"time"

	"github.com/Azure/msi-acrpull/pkg/authorizer/mock_authorizer"
	"github.com/Azure/msi-acrpull/pkg/authorizer/types"

	"github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Authorizer Tests", func() {
	var (
		mockCtrl *gomock.Controller
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
	})

	Context("Acquire ACR Access Token", func() {
		It("Get ACR Token with Resource ID via Managed Identity Successfully", func() {
			armToken, err := getTestArmToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			acrToken, err := getTestAcrToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			mitr := mock_authorizer.NewMockMIARMTokenRetriever(mockCtrl)
			te := mock_authorizer.NewMockACRTokenExchanger(mockCtrl)

			az := &Authorizer{
				managedIdentityTokenRetriever: mitr,
				tokenExchanger:                te,
			}

			mitr.EXPECT().MIAcquireARMToken("", testResourceID).Return(armToken, nil).Times(1)
			te.EXPECT().ExchangeACRAccessToken(armToken, testTenantID, testACR).Return(acrToken, nil).Times(1)

			t, err := az.AcquireACRAccessTokenWithManagedIdentity("", testResourceID, testACR)
			Expect(err).To(BeNil())
			Expect(t).NotTo(BeNil())
			Expect(t).To(Equal(acrToken))
		})

		It("Get ACR Token with Client ID via Managed Identity Successfully", func() {
			armToken, err := getTestArmToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			acrToken, err := getTestAcrToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			mitr := mock_authorizer.NewMockMIARMTokenRetriever(mockCtrl)
			te := mock_authorizer.NewMockACRTokenExchanger(mockCtrl)

			az := &Authorizer{
				managedIdentityTokenRetriever: mitr,
				tokenExchanger:                te,
			}

			mitr.EXPECT().MIAcquireARMToken(testClientID, "").Return(armToken, nil).Times(1)
			te.EXPECT().ExchangeACRAccessToken(armToken, testTenantID, testACR).Return(acrToken, nil).Times(1)

			t, err := az.AcquireACRAccessTokenWithManagedIdentity(testClientID, "", testACR)
			Expect(err).To(BeNil())
			Expect(t).NotTo(BeNil())
			Expect(t).To(Equal(acrToken))
		})

		It("Returns Error when ARM Token Retrieve Failed", func() {
			mitr := mock_authorizer.NewMockMIARMTokenRetriever(mockCtrl)
			te := mock_authorizer.NewMockACRTokenExchanger(mockCtrl)

			az := &Authorizer{
				managedIdentityTokenRetriever: mitr,
				tokenExchanger:                te,
			}

			mitr.EXPECT().MIAcquireARMToken(testClientID, "").Return(types.AccessToken(""), errors.New("test error")).Times(1)

			t, err := az.AcquireACRAccessTokenWithManagedIdentity(testClientID, "", testACR)
			Expect(string(t)).To(Equal(""))
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("test error"))
		})

		It("Get ACR Token with Client ID via Workload Identity Successfully", func() {
			armToken, err := getTestArmToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			acrToken, err := getTestAcrToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			witr := mock_authorizer.NewMockWIARMTokenRetriever(mockCtrl)
			te := mock_authorizer.NewMockACRTokenExchanger(mockCtrl)

			az := &Authorizer{
				workloadIdentityTokenRetriever: witr,
				tokenExchanger:                 te,
			}

			ctx := context.Background()
			witr.EXPECT().WIAcquireARMToken(ctx, testClientID, testTenantID).Return(armToken, nil).Times(1)
			te.EXPECT().ExchangeACRAccessToken(armToken, testTenantID, testACR).Return(acrToken, nil).Times(1)

			t, err := az.AcquireACRAccessTokenWithWorkloadIdentity(ctx, testClientID, testTenantID, testACR)
			Expect(err).To(BeNil())
			Expect(t).NotTo(BeNil())
			Expect(t).To(Equal(acrToken))
		})
	})
})
