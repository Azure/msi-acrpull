package controllers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
	"github.com/Azure/msi-acrpull/pkg/authorizer/types"
)

type errorFakeCtrlRuntimeClient struct {
	client.Client
}

func (e *errorFakeCtrlRuntimeClient) Get(ctx context.Context, key client.ObjectKey, obj runtime.Object) error {
	return k8serrors.NewConflict(
		schema.GroupResource{
			Group:    "msi-acrpull.microsoft.com",
			Resource: "acrpullbinding",
		},
		"test",
		errors.New("test error"))
}

var _ = msiacrpullv1beta1.AddToScheme(scheme.Scheme)

var _ = Describe("AcrPullBinding Controller Tests", func() {
	Context("Reconcile", func() {
		It("Should not return error when the acr pull binding is not found", func() {
			reconciler := &AcrPullBindingReconciler{
				Client: fake.NewFakeClientWithScheme(scheme.Scheme),
				Log:    ctrl.Log.WithName("controllers").WithName("acrpullbinding-controller"),
				Scheme: scheme.Scheme,
			}
			req := ctrl.Request{
				NamespacedName: k8stypes.NamespacedName{
					Namespace: "default",
				},
			}
			_, err := reconciler.Reconcile(req)
			Expect(err).To(BeNil())
		})

		/*
			It("Should use defaults when no parameters defined", func() {
				mockCtrl := gomock.NewController(GinkgoT())
				fakeAuth := mock_authorizer.NewMockInterface(mockCtrl)

				reconciler := &AcrPullBindingReconciler{
					Client:                           fake.NewFakeClientWithScheme(scheme.Scheme),
					Log:                              ctrl.Log.WithName("controllers").WithName("acrpullbinding-controller"),
					Scheme:                           scheme.Scheme,
					Auth:                             fakeAuth,
					DefaultManagedIdentityResourceID: "defaultResourceID",
					DefaultACRServer:                 "DefaultACRServer",
				}
				fakeAuth.EXPECT().AcquireACRAccessTokenWithResourceID(
					gomock.Eq(reconciler.DefaultManagedIdentityResourceID),
					gomock.Eq(reconciler.DefaultACRServer)).Times(1)

				acrBinding := &msiacrpullv1beta1.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "test",
						Namespace:  "default",
						Finalizers: []string{},
					},
				}
				reconciler.Create(context.TODO(), acrBinding)

				req := ctrl.Request{
					NamespacedName: k8stypes.NamespacedName{
						Namespace: "default",
						Name:      "test",
					},
				}
				reconciler.Reconcile(req)
				mockCtrl.Finish()
			})
		*/

		It("Should return error when getting acr pull binding returns error other than NotFound", func() {
			reconciler := &AcrPullBindingReconciler{
				Client: &errorFakeCtrlRuntimeClient{fake.NewFakeClientWithScheme(scheme.Scheme)},
				Log:    ctrl.Log.WithName("controllers").WithName("acrpullbinding-controller"),
				Scheme: scheme.Scheme,
			}
			req := ctrl.Request{
				NamespacedName: k8stypes.NamespacedName{
					Namespace: "default",
				},
			}
			_, err := reconciler.Reconcile(req)
			Expect(err).To(Not(BeNil()))
			Expect(err.Error()).To(ContainSubstring("test error"))
		})
	})

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
		It("Should add finalizer to acr pull binding", func() {
			acrBinding := &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test",
					Namespace:  "default",
					Finalizers: []string{},
				},
			}
			reconciler := &AcrPullBindingReconciler{
				Client: fake.NewFakeClientWithScheme(scheme.Scheme, acrBinding),
				Log:    ctrl.Log.WithName("controllers").WithName("acrpullbinding-controller"),
				Scheme: scheme.Scheme,
			}
			log := reconciler.Log.WithValues("acrpullbinding", "default")
			ctx := context.Background()
			err := reconciler.addFinalizer(ctx, acrBinding, log)
			Expect(err).To(BeNil())
			Expect(acrBinding.Finalizers).To(HaveLen(1))
			Expect(acrBinding.Finalizers[0]).To(Equal("msi-acrpull.microsoft.com"))
		})
	})

	Context("removeFinalizer", func() {
		It("Should remove finalizer from acr pull binding", func() {
			serviceAccountName := "sa1"
			acrBinding := &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Finalizers: []string{
						"msi-acrpull.microsoft.com",
					},
				},
			}
			serviceAccount := &v1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      serviceAccountName,
					Namespace: "default",
				},
			}
			reconciler := &AcrPullBindingReconciler{
				Client: fake.NewFakeClientWithScheme(scheme.Scheme, acrBinding, serviceAccount),
				Log:    ctrl.Log.WithName("controllers").WithName("acrpullbinding-controller"),
				Scheme: scheme.Scheme,
			}
			log := reconciler.Log.WithValues("acrpullbinding", "default")
			ctx := context.Background()
			req := ctrl.Request{
				NamespacedName: k8stypes.NamespacedName{
					Namespace: "default",
				},
			}
			err := reconciler.removeFinalizer(ctx, acrBinding, req, serviceAccountName, log)
			Expect(err).To(BeNil())
			Expect(acrBinding.Finalizers).To(BeEmpty())
		})

		It("Should remove finalizer from acr pull binding when service account doesn't exist", func() {
			serviceAccountName := "sa1"
			acrBinding := &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Finalizers: []string{
						"msi-acrpull.microsoft.com",
					},
				},
			}
			reconciler := &AcrPullBindingReconciler{
				Client: fake.NewFakeClientWithScheme(scheme.Scheme, acrBinding),
				Log:    ctrl.Log.WithName("controllers").WithName("acrpullbinding-controller"),
				Scheme: scheme.Scheme,
			}
			log := reconciler.Log.WithValues("acrpullbinding", "default")
			ctx := context.Background()
			req := ctrl.Request{
				NamespacedName: k8stypes.NamespacedName{
					Namespace: "default",
				},
			}
			err := reconciler.removeFinalizer(ctx, acrBinding, req, serviceAccountName, log)
			Expect(err).To(BeNil())
			Expect(acrBinding.Finalizers).To(BeEmpty())
		})
	})

	Context("updateServiceAccount", func() {
		It("Should update service account with image pull secret reference", func() {
			type testCase struct {
				serviceAccountName string
			}

			testCases := []testCase{
				{"default"},
				{"userdefined"},
			}

			for _, testCase := range testCases {
				serviceAccountName := testCase.serviceAccountName
				acrBinding := &msiacrpullv1beta1.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test",
						Namespace: "default",
						Finalizers: []string{
							msiAcrPullFinalizerName,
						},
					},
				}
				serviceAccount := &v1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      serviceAccountName,
						Namespace: "default",
					},
				}
				reconciler := &AcrPullBindingReconciler{
					Client: fake.NewFakeClientWithScheme(scheme.Scheme, acrBinding, serviceAccount),
					Log:    ctrl.Log.WithName("controllers").WithName("acrpullbinding-controller"),
					Scheme: scheme.Scheme,
				}
				log := reconciler.Log.WithValues("acrpullbinding", "default")
				ctx := context.Background()
				req := ctrl.Request{
					NamespacedName: k8stypes.NamespacedName{
						Namespace: "default",
					},
				}
				err := reconciler.updateServiceAccount(ctx, acrBinding, req, serviceAccountName, log)
				Expect(err).To(BeNil())

				saNamespacedName := k8stypes.NamespacedName{
					Name:      serviceAccountName,
					Namespace: "default",
				}
				err = reconciler.Client.Get(ctx, saNamespacedName, serviceAccount)
				Expect(err).To(BeNil())
				Expect(serviceAccount.ImagePullSecrets).To(HaveLen(1))
				Expect(serviceAccount.ImagePullSecrets[0].Name).To(Equal("test-msi-acrpull-secret"))
			}
		})
	})

	Context("appendImagePullSecretRef", func() {
		It("Should append image pull secret reference to service account", func() {
			serviceAccount := &v1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: "default",
				},
			}
			appendImagePullSecretRef(serviceAccount, "test")
			Expect(serviceAccount.ImagePullSecrets).To(HaveLen(1))
			Expect(serviceAccount.ImagePullSecrets[0].Name).To(Equal("test"))
		})
	})

	Context("imagePullSecretRefExist", func() {
		It("Should check if image pull secret reference exists given name", func() {
			imagePullSecretRef := []v1.LocalObjectReference{
				{
					Name: "test-msi-acrpull-secret",
				},
			}
			exist := imagePullSecretRefExist(imagePullSecretRef, "test-msi-acrpull-secret")
			Expect(exist).To(BeTrue())

			exist = imagePullSecretRefExist(imagePullSecretRef, "not-exist")
			Expect(exist).To(BeFalse())
		})
	})

	Context("removeImagePullSecretRef", func() {
		It("Should remove image pull secret reference", func() {
			imagePullSecretRef := []v1.LocalObjectReference{
				{
					Name: "test-msi-acrpull-secret",
				},
			}
			newImagePullSecretRef := removeImagePullSecretRef(imagePullSecretRef, "test-msi-acrpull-secret")
			Expect(newImagePullSecretRef).To(BeEmpty())
		})
	})

	Context("containsString", func() {
		It("Should check if an array of strings contains a string", func() {
			strings := []string{"test-string"}
			contains := containsString(strings, "test-string")
			Expect(contains).To(BeTrue())

			contains = containsString(strings, "not-exist")
			Expect(contains).To(BeFalse())
		})
	})

	Context("removeString", func() {
		It("Should remove string from an array", func() {
			strings := []string{"test-string"}
			newStrings := removeString(strings, "test-string")
			Expect(newStrings).To(BeEmpty())
		})
	})

	Context("specOrDefaultTest", func() {
		It("should deduplicate double slash", func() {
			reconciler := &AcrPullBindingReconciler{}
			spec := msiacrpullv1beta1.AcrPullBindingSpec{
				ManagedIdentityResourceID: "/resourcegroup//doubleslash/singleslash/",
			}
			_, msiResourceId, _ := specOrDefault(reconciler, spec)
			Expect(msiResourceId).To(Equal("/resourcegroup/doubleslash/singleslash"))
		})
	})
	Context("getServiceAccountName", func() {
		It("Should get service account name", func() {
			Expect(getServiceAccountName("")).To(Equal(defaultServiceAccountName))
			Expect(getServiceAccountName("userspecified")).To(Equal("userspecified"))
		})
	})
})

func getTestToken(exp int64) (types.AccessToken, error) {
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

	return types.AccessToken(tokenString), nil
}
