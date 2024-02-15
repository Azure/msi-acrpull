package authorizer

import (
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Util Tests", func() {

	Context("Generate Docker Config", func() {
		It("Generate correct Docker Config JSON", func() {
			acrToken, err := getTestAcrToken(time.Now().Add(time.Hour).Unix(), signingKey)
			Expect(err).ToNot(HaveOccurred())

			cfg := CreateACRDockerCfg(testACR, acrToken)

			var cfgJSON interface{}
			err = json.Unmarshal([]byte(cfg), &cfgJSON)

			Expect(err).To(BeNil())
		})
	})
})
