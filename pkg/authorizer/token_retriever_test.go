package authorizer

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("Token Retriever Tests", func() {
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

	Context("Retrieve ARM Token", func() {
		It("Get ARM Token with Resource ID Successfully", func() {
			armToken, err := getTestArmToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			tokenResp := &tokenResponse{AccessToken: string(armToken)}

			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/", fmt.Sprintf("mi_res_id=%s&resource=https://management.azure.com/&api-version=2018-02-01", testResourceID)),
					ghttp.RespondWithJSONEncoded(200, tokenResp),
				))

			tr := newTestTokenRetriever(server, defaultCacheExpirationInSeconds)
			token, err := tr.AcquireARMToken(context.Background(), "", testResourceID)

			Expect(err).To(BeNil())
			Expect(server.ReceivedRequests()).Should(HaveLen(1))
			Expect(token).To(Equal(armToken))
		})

		It("Get ARM Token Against Custom ARM Resource Successfully", func() {
			armToken, err := getTestArmToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			tokenResp := &tokenResponse{AccessToken: string(armToken)}

			os.Setenv(customARMResourceEnvVar, "https://management.usgovcloudapi.net/")

			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/", fmt.Sprintf("mi_res_id=%s&resource=https://management.usgovcloudapi.net/&api-version=2018-02-01", testResourceID)),
					ghttp.RespondWithJSONEncoded(200, tokenResp),
				))

			tr := newTestTokenRetriever(server, defaultCacheExpirationInSeconds)
			token, err := tr.AcquireARMToken(context.Background(), "", testResourceID)

			os.Unsetenv(customARMResourceEnvVar)

			Expect(err).To(BeNil())
			Expect(server.ReceivedRequests()).Should(HaveLen(1))
			Expect(token).To(Equal(armToken))
		})

		It("Get ARM Token with Client ID Successfully", func() {
			armToken, err := getTestArmToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			tokenResp := &tokenResponse{AccessToken: string(armToken)}

			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/", fmt.Sprintf("client_id=%s&resource=https://management.azure.com/&api-version=2018-02-01", testClientID)),
					ghttp.RespondWithJSONEncoded(200, tokenResp),
				))

			tr := newTestTokenRetriever(server, defaultCacheExpirationInSeconds)
			token, err := tr.AcquireARMToken(context.Background(), testClientID, "")

			Expect(err).To(BeNil())
			Expect(server.ReceivedRequests()).Should(HaveLen(1))
			Expect(token).To(Equal(armToken))
		})

		It("Returns error when identity not found", func() {
			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/", fmt.Sprintf("client_id=%s&resource=https://management.azure.com/&api-version=2018-02-01", testClientID)),
					ghttp.RespondWith(404, ""),
				))

			tr := newTestTokenRetriever(server, defaultCacheExpirationInSeconds)
			token, err := tr.AcquireARMToken(context.Background(), testClientID, "")

			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("404"))
			Expect(server.ReceivedRequests()).Should(HaveLen(1))
			Expect(string(token)).To(Equal(""))
		})

		It("Get ARM Token with cache using client ID", func() {
			armToken, err := getTestArmToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			tokenResp := &tokenResponse{AccessToken: string(armToken)}

			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/", fmt.Sprintf("client_id=%s&resource=https://management.azure.com/&api-version=2018-02-01", testClientID)),
					ghttp.RespondWithJSONEncoded(200, tokenResp),
				))

			tr := newTestTokenRetriever(server, defaultCacheExpirationInSeconds*1000)
			token, err := tr.AcquireARMToken(context.Background(), testClientID, "")
			Expect(err).To(BeNil())
			Expect(token).To(Equal(armToken))
			Expect(server.ReceivedRequests()).Should(HaveLen(1))

			token, err = tr.AcquireARMToken(context.Background(), testClientID, "")
			Expect(err).To(BeNil())
			Expect(token).To(Equal(armToken))
			Expect(server.ReceivedRequests()).Should(HaveLen(1))
		})

		It("Get ARM Token with cache using resource ID", func() {
			armToken, err := getTestArmToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			tokenResp := &tokenResponse{AccessToken: string(armToken)}

			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/", fmt.Sprintf("mi_res_id=%s&resource=https://management.azure.com/&api-version=2018-02-01", testResourceID)),
					ghttp.RespondWithJSONEncoded(200, tokenResp),
				))

			tr := newTestTokenRetriever(server, defaultCacheExpirationInSeconds*1000)
			token, err := tr.AcquireARMToken(context.Background(), "", testResourceID)
			Expect(err).To(BeNil())
			Expect(token).To(Equal(armToken))
			Expect(server.ReceivedRequests()).Should(HaveLen(1))

			token, err = tr.AcquireARMToken(context.Background(), "", testResourceID)
			Expect(err).To(BeNil())
			Expect(token).To(Equal(armToken))
			Expect(server.ReceivedRequests()).Should(HaveLen(1))
		})

		It("Refresh ARM Token if cache expired", func() {
			armToken, err := getTestArmToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			tokenResp := &tokenResponse{AccessToken: string(armToken)}

			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/", fmt.Sprintf("client_id=%s&resource=https://management.azure.com/&api-version=2018-02-01", testClientID)),
					ghttp.RespondWithJSONEncoded(200, tokenResp),
				),
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/", fmt.Sprintf("client_id=%s&resource=https://management.azure.com/&api-version=2018-02-01", testClientID)),
					ghttp.RespondWithJSONEncoded(200, tokenResp),
				))

			// set cache expire immediately
			tr := newTestTokenRetriever(server, 0)
			token, err := tr.AcquireARMToken(context.Background(), testClientID, "")
			Expect(err).To(BeNil())
			Expect(token).To(Equal(armToken))
			Expect(server.ReceivedRequests()).Should(HaveLen(1))

			token, err = tr.AcquireARMToken(context.Background(), testClientID, "")
			Expect(err).To(BeNil())
			Expect(token).To(Equal(armToken))
			Expect(server.ReceivedRequests()).Should(HaveLen(2))
		})
	})
})

func newTestTokenRetriever(server *ghttp.Server, cacheExpirationInMilliSeconds int) *TokenRetriever {
	client := newRateLimitedClient()
	client.httpClient = server.HTTPTestServer.Client()

	return &TokenRetriever{
		metadataEndpoint: server.URL(),
		cache:            sync.Map{},
		cacheExpiration:  time.Duration(cacheExpirationInMilliSeconds) * time.Millisecond,
		client:           client,
	}
}
