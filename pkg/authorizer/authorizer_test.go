package authorizer

import (
	"context"
	"errors"
	"time"

	"github.com/Azure/msi-acrpull/pkg/authorizer/mock_authorizer"
	"github.com/Azure/msi-acrpull/pkg/authorizer/types"

	"github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Authorizer Tests", func() {
	var (
		mockCtrl *gomock.Controller
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
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

			tr.EXPECT().AcquireARMToken(context.Background(), "", testResourceID).Return(armToken, nil).Times(1)
			te.EXPECT().ExchangeACRAccessToken(context.Background(), armToken, testACR).Return(acrToken, nil).Times(1)

			t, err := az.AcquireACRAccessTokenWithResourceID(context.Background(), testResourceID, testACR)
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

			tr.EXPECT().AcquireARMToken(context.Background(), testClientID, "").Return(armToken, nil).Times(1)
			te.EXPECT().ExchangeACRAccessToken(context.Background(), armToken, testACR).Return(acrToken, nil).Times(1)

			t, err := az.AcquireACRAccessTokenWithClientID(context.Background(), testClientID, testACR)
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

			tr.EXPECT().AcquireARMToken(context.Background(), testClientID, "").Return(types.AccessToken(""), errors.New("test error")).Times(1)

			t, err := az.AcquireACRAccessTokenWithClientID(context.Background(), testClientID, testACR)
			Expect(string(t)).To(Equal(""))
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("test error"))
		})
	})
})
