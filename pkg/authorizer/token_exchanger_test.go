package authorizer

import (
	"context"
	"net/url"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("Token Exchanger Tests", func() {
	var (
		server *ghttp.Server
	)

	BeforeEach(func() {
		server = ghttp.NewServer()
	})

	AfterEach(func() {
		//shut down the server between tests
		server.Close()
	})

	Context("Exchange ACR Access Token", func() {
		It("Get ACR Token Successfully", func() {
			armToken, err := getTestArmToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			acrToken, err := getTestAcrToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			tokenResp := &tokenResponse{RefreshToken: string(acrToken)}

			ul, err := url.Parse(server.URL())
			Expect(err).ToNot(HaveOccurred())

			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("POST", "/oauth2/exchange"),
					ghttp.VerifyContentType("application/x-www-form-urlencoded"),
					ghttp.VerifyFormKV("service", ul.Hostname()),
					ghttp.VerifyFormKV("grant_type", "access_token"),
					ghttp.VerifyFormKV("access_token", string(armToken)),
					ghttp.RespondWithJSONEncoded(200, tokenResp),
				))

			te := newTestTokenExchanger(server)
			token, err := te.ExchangeACRAccessToken(context.Background(), GinkgoLogr, armToken, ul.Host)

			Expect(err).To(BeNil())
			Expect(server.ReceivedRequests()).Should(HaveLen(1))
			Expect(token).To(Equal(acrToken))
		})

		It("Returns error when ACR reject token exchange", func() {
			armToken, err := getTestArmToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			ul, err := url.Parse(server.URL())
			Expect(err).ToNot(HaveOccurred())

			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("POST", "/oauth2/exchange"),
					ghttp.VerifyContentType("application/x-www-form-urlencoded"),
					ghttp.VerifyFormKV("service", ul.Hostname()),
					ghttp.VerifyFormKV("grant_type", "access_token"),
					ghttp.VerifyFormKV("access_token", string(armToken)),
					ghttp.RespondWith(403, "Unauthorized"),
				))

			te := newTestTokenExchanger(server)
			token, err := te.ExchangeACRAccessToken(context.Background(), GinkgoLogr, armToken, ul.Host)

			Expect(err).NotTo(BeNil())
			Expect(server.ReceivedRequests()).Should(HaveLen(1))
			Expect(string(token)).To(Equal(""))

			Expect(err.Error()).To(ContainSubstring("Unauthorized"))
		})
	})
})

func newTestTokenExchanger(server *ghttp.Server) *TokenExchanger {
	client := newRateLimitedClient()
	client.httpClient = server.HTTPTestServer.Client()

	return &TokenExchanger{
		acrServerScheme: "http",
		client:          client,
	}
}
