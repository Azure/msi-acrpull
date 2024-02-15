package types

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAuthorizer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Authorizer Types Test Suite")
}
