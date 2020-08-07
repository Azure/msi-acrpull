package token

import (
"testing"

. "github.com/onsi/ginkgo"
. "github.com/onsi/gomega"
)

func TestEndpoints(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Token Test Suite")
}
