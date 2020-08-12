package controllers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
	"github.com/Azure/msi-acrpull/pkg/auth"
)

var _ = Describe("AcrPullBinding Controller Tests", func() {
	Context("getTokenRefreshDuration", func() {
		It("Should return 0 for negative durations", func() {
			token, err := getTestToken(time.Now().Add(-time.Hour).Unix())
			Expect(err).ToNot(HaveOccurred())

			refreshDuration := getTokenRefreshDuration(token)
			Expect(int(refreshDuration)).To(Equal(0))
		})

		It("Should return positive duration when exp is outside refresh buffer", func() {
			exp := time.Now().Add(tokenRefreshBuffer + time.Hour).Unix()

			token, err := getTestToken(exp)
			Expect(err).ToNot(HaveOccurred())

			refreshDuration := getTokenRefreshDuration(token)
			Expect(refreshDuration > 0).To(BeTrue())
		})
	})

	Context("appendImagePullSecretRef", func() {
		It("Should append image pull secret reference to slice", func() {
			serviceAccount := &v1.ServiceAccount{
				ImagePullSecrets: []v1.LocalObjectReference{
					{Name: "secret1"},
				},
			}
			appendImagePullSecretRef(serviceAccount, "secret2")
			Expect(len(serviceAccount.ImagePullSecrets)).To(Equal(2))
		})
	})

	Context("addFinalizer", func() {
		FIt("Should add finalizer to acr pull binding", func() {
			reconciler := &AcrPullBindingReconciler{
				Client: k8sManager.GetClient(),
				Log:    ctrl.Log.WithName("controllers").WithName("SecretScope"),
				Scheme: k8sManager.GetScheme(),
			}
			log := reconciler.Log.WithValues("acrpullbinding", "system")
			ctx := context.Background()
			acrBinding := &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{
					Finalizers: []string{},
				},
			}
			reconciler.addFinalizer(ctx, acrBinding, log)
			Expect(acrBinding.Finalizers).To(HaveLen(1))
		})
	})
})

func getTestToken(exp int64) (auth.AccessToken, error) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).ToNot(HaveOccurred())

	claims := jwt.MapClaims{
		"aud":        "test.azurecr.io",
		"exp":        exp,
		"grant_type": "refresh_token",
		"iat":        time.Now().AddDate(0, 0, -2).Unix(),
		"version":    1.0,
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

	return auth.AccessToken(tokenString), nil
}
