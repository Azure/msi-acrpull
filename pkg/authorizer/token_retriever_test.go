package authorizer

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
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

			tr := &TokenRetriever{server.URL()}
			token, err := tr.AcquireARMToken("", testResourceID)

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

			tr := &TokenRetriever{server.URL()}
			token, err := tr.AcquireARMToken(testClientID, "")

			Expect(err).To(BeNil())
			Expect(server.ReceivedRequests()).Should(HaveLen(1))
			Expect(token).To(Equal(armToken))
		})
	})
})
