package controller

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/msi-acrpull/pkg/authorizer/mock_authorizer"
	"github.com/go-logr/logr/testr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
	"go.uber.org/mock/gomock"

	corev1 "k8s.io/api/core/v1"
	apimachineryvalidation "k8s.io/apimachinery/pkg/api/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	testingclock "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
)

// generating lots of PKI in environments where compute and/or entropy is limited (like in test containers)
// can be very slow - instead, we use precomputed PKI and allow for re-generating it if necessary
//
//go:embed testdata
var testdata embed.FS

// noncryptographic for faster testing
// DO NOT COPY THIS CODE
var insecureRand = rand.New(rand.NewSource(0))

func privateKey(t *testing.T) crypto.PrivateKey {
	if os.Getenv("REGENERATE_PKI") != "" {
		t.Log("$REGENERATE_PKI set, generating a new private key")
		pk, err := rsa.GenerateKey(insecureRand, 2048)
		if err != nil {
			t.Fatalf("failed to generate private key: %v", err)
		}

		der := x509.MarshalPKCS1PrivateKey(pk)
		pkb := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

		if err := os.WriteFile(filepath.Join("testdata", "singing.key"), pkb, 0666); err != nil {
			t.Fatalf("failed to write re-generated private key: %v", err)
		}

		return pk
	}

	t.Log("loading private key from disk, use $REGENERATE_PKI to generate a new one")
	pemb, err := testdata.ReadFile(filepath.Join("testdata", "singing.key"))
	if err != nil {
		t.Fatalf("failed to read private key: %v", err)
	}
	der, _ := pem.Decode(pemb)
	key, err := x509.ParsePKCS1PrivateKey(der.Bytes)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}
	return key
}

func getTestToken(t *testing.T, now func() time.Time, expiry time.Time) azcore.AccessToken {
	signingKey := privateKey(t)

	claims := jwt.MapClaims{
		"aud":        "test.azurecr.io",
		"exp":        expiry.Unix(),
		"grant_type": "refresh_token",
		"iat":        now().AddDate(0, 0, -2).Unix(),
		"version":    1.0,
		"permissions": map[string]interface{}{
			"actions": []string{"read"},
		},
		"jti": "bb8d6d3d-c7b0-4f96-a390-8738f730e8c6",
		"iss": "Azure Container Registry",
		"nbf": now().AddDate(0, 0, -1).Unix(),
	}

	token := jwt.NewWithClaims(&fakeRSAMethod{"ES256", crypto.SHA256, 32, 256}, claims)
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return azcore.AccessToken{
		Token:     tokenString,
		ExpiresOn: expiry,
	}
}

// the JWT library doesn't allow mocking out the source of randomness for testing, so it's not possible to
// write deterministic tests; copy the RSA implementation but switch out our reader for testing
type fakeRSAMethod struct {
	Name      string
	Hash      crypto.Hash
	KeySize   int
	CurveBits int
}

func (m fakeRSAMethod) Verify(signingString string, sig []byte, key interface{}) error {
	return nil
}

func (m fakeRSAMethod) Sign(signingString string, key interface{}) ([]byte, error) {
	var rsaKey *rsa.PrivateKey
	var ok bool

	// Validate type of key
	if rsaKey, ok = key.(*rsa.PrivateKey); !ok {
		return nil, jwt.ErrInvalidKey
	}

	// Create the hasher
	if !m.Hash.Available() {
		return nil, jwt.ErrHashUnavailable
	}

	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	// Sign the string and return the encoded bytes
	if sigBytes, err := rsa.SignPKCS1v15(insecureRand, rsaKey, m.Hash, hasher.Sum(nil)); err == nil {
		return sigBytes, nil
	} else {
		return nil, err
	}
}

func (m fakeRSAMethod) Alg() string {
	return m.Name
}

var _ jwt.SigningMethod = (*fakeRSAMethod)(nil)

func Test_ACRPullBindingController_reconcile(t *testing.T) {
	const (
		defaultManagedIdentityResourceID = "defaultResourceID"
		defaultACRServer                 = "DefaultACRServer"
	)

	if err := msiacrpullv1beta1.AddToScheme(scheme.Scheme); err != nil {
		t.Fatalf("failed to set up scheme: %v", err)
	}

	theTime, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
	if err != nil {
		t.Fatalf("could not parse time: %v", err)
	}
	fakeClock := testingclock.NewFakeClock(theTime)

	longExpiry := fakeClock.Now().Add(24 * time.Hour).UTC()
	futureToken := getTestToken(t, fakeClock.Now, longExpiry)

	otherExpiry := fakeClock.Now().Add(12 * time.Hour).UTC()
	otherToken := getTestToken(t, fakeClock.Now, otherExpiry)

	recentExpiry := fakeClock.Now().Add(1 * time.Minute).UTC()
	// acquired the expiring token like so, and used to encode the auth JSON for the secret
	// expiringToken := getTestToken(t, fakeClock.Now, recentExpiry)

	for _, testCase := range []struct {
		name                       string
		acrBinding                 *msiacrpullv1beta1.AcrPullBinding
		serviceAccount             *corev1.ServiceAccount
		pullSecret                 *corev1.Secret
		referencingServiceAccounts []corev1.ServiceAccount

		registerTokenCall func(*mock_authorizer.MockInterface)

		output *action
	}{
		{
			name: "binding missing finalizer gets one",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding"},
			},
			output: &action{
				updatePullBinding: &msiacrpullv1beta1.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				},
			},
		},
		{
			name: "missing service account errors",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta1.AcrPullBindingSpec{
					ServiceAccountName: "missing",
				},
			},
			output: &action{
				updatePullBindingStatus: &msiacrpullv1beta1.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
					Spec: msiacrpullv1beta1.AcrPullBindingSpec{
						ServiceAccountName: "missing",
					},
					Status: msiacrpullv1beta1.AcrPullBindingStatus{
						Error: `service account "missing" not found`,
					},
				},
			},
		},
		{
			name: "binding missing pull credential mints a new one",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta1.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					Scope:              "repository:testing:pull,push",
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
			},
			pullSecret: nil,
			registerTokenCall: func(mock *mock_authorizer.MockInterface) {
				mock.EXPECT().AcquireACRAccessToken(
					context.Background(),
					gomock.Eq(defaultManagedIdentityResourceID),
					gomock.Eq(""),
					gomock.Eq(defaultACRServer),
					gomock.Eq("repository:testing:pull,push")).
					Return(futureToken, nil).
					Times(1)
			},
			output: &action{
				createSecret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "acr-pull-binding-37d7ayn69u",
						Labels: map[string]string{
							"acr.microsoft.com/binding": "binding",
						},
						Annotations: map[string]string{
							"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
							"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
							"acr.microsoft.com/token.inputs":  "2wucoufm4eqegr6z5nmg00bvmwguubf86kfxk6yir9pw",
						},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "msi-acrpull.microsoft.com/v1beta1",
								Kind:               "AcrPullBinding",
								Name:               "binding",
								Controller:         ptr.To(true),
								BlockOwnerDeletion: ptr.To(true),
							},
						},
					},
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						".dockerconfigjson": []byte(`{"auths":{"DefaultACRServer":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
					},
				},
			},
		},
		{
			name: "failure getting pull credential exposed",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta1.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
			},
			pullSecret: nil,
			registerTokenCall: func(mock *mock_authorizer.MockInterface) {
				mock.EXPECT().AcquireACRAccessToken(
					context.Background(),
					gomock.Eq(defaultManagedIdentityResourceID),
					gomock.Eq(""),
					gomock.Eq(defaultACRServer),
					gomock.Eq("")).
					Return(azcore.AccessToken{}, errors.New("oops")).
					Times(1)
			},
			output: &action{
				updatePullBindingStatus: &msiacrpullv1beta1.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
					Spec: msiacrpullv1beta1.AcrPullBindingSpec{
						ServiceAccountName: "delegate",
					},
					Status: msiacrpullv1beta1.AcrPullBindingStatus{
						Error: `failed to retrieve ACR access token: oops`,
					},
				},
			},
		},
		{
			name: "binding with pull credential updates the service account",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta1.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
			},
			pullSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding-37d7ayn69u",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "2wucoufm4eqegr6z5nmg00bvmwguubf86kfxk6yir9pw",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "msi-acrpull.microsoft.com/v1beta1",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"DefaultACRServer":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			},
			output: &action{
				updateServiceAccount: &corev1.ServiceAccount{
					ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding-37d7ayn69u"}},
				},
			},
		},
		{
			name: "binding with pull credential recorded on service account updates binding status",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta1.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding-37d7ayn69u"}},
			},
			pullSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding-37d7ayn69u",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "2wucoufm4eqegr6z5nmg00bvmwguubf86kfxk6yir9pw",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "msi-acrpull.microsoft.com/v1beta1",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"DefaultACRServer":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			},
			output: &action{
				updatePullBindingStatus: &msiacrpullv1beta1.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
					Spec: msiacrpullv1beta1.AcrPullBindingSpec{
						ServiceAccountName: "delegate",
					},
					Status: msiacrpullv1beta1.AcrPullBindingStatus{
						LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
						TokenExpirationTime:  &metav1.Time{Time: longExpiry},
					},
				},
			},
		},
		{
			name: "expiring pull credential mints a new one",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta1.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
				},
				Status: msiacrpullv1beta1.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: recentExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding-37d7ayn69u"}},
			},
			pullSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding-37d7ayn69u",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  recentExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "2wucoufm4eqegr6z5nmg00bvmwguubf86kfxk6yir9pw",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "msi-acrpull.microsoft.com/v1beta1",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"DefaultACRServer":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYyMTQzMDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.pt3Ra4QKcq7mHX3Qp9-0vzpzQKooPJmviQLWazhlcgHjtnf-QL3ZZYVy1F06ExmznYbtU1ADGOBuhtn94ORezYZ5Dg3eSS5hSpuSnJdpGQlkzLxsfyFUszKvKraqQ72hcRZ5kYkRd9dMT-yGphMoIqP3crfrzFR4ZIwf0JBMxiS_iNIvi7RHpg0lBLDZdP739lNQ6oY-O76H_SuYbgJ7HP0nssVy0DlQF6HT9X6Qq1gTCxuK28Juo2yDeTSaagjihgXeUc4zH2cMKz6f5deoIr3i7BNMuXVHOyXeEcShohHmfUFAAmr_LiotZsTeEXVaMkaoRFlCBb2bv2lM9PzFyw","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXlNVFF6TURVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLnB0M1JhNFFLY3E3bUhYM1FwOS0wdnpwelFLb29QSm12aVFMV2F6aGxjZ0hqdG5mLVFMM1paWVZ5MUYwNkV4bXpuWWJ0VTFBREdPQnVodG45NE9SZXpZWjVEZzNlU1M1aFNwdVNuSmRwR1Fsa3pMeHNmeUZVc3pLdktyYXFRNzJoY1JaNWtZa1JkOWRNVC15R3BoTW9JcVAzY3JmcnpGUjRaSXdmMEpCTXhpU19pTkl2aTdSSHBnMGxCTERaZFA3MzlsTlE2b1ktTzc2SF9TdVliZ0o3SFAwbnNzVnkwRGxRRjZIVDlYNlFxMWdUQ3h1SzI4SnVvMnlEZVRTYWFnamloZ1hlVWM0ekgyY01LejZmNWRlb0lyM2k3Qk5NdVhWSE95WGVFY1Nob2hIbWZVRkFBbXJfTGlvdFpzVGVFWFZhTWthb1JGbENCYjJidjJsTTlQekZ5dw=="}}}`),
				},
			},
			registerTokenCall: func(mock *mock_authorizer.MockInterface) {
				mock.EXPECT().AcquireACRAccessToken(
					context.Background(),
					gomock.Eq(defaultManagedIdentityResourceID),
					gomock.Eq(""),
					gomock.Eq(defaultACRServer),
					gomock.Eq("")).
					Return(futureToken, nil).
					Times(1)
			},
			output: &action{
				updateSecret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "acr-pull-binding-37d7ayn69u",
						Labels: map[string]string{
							"acr.microsoft.com/binding": "binding",
						},
						Annotations: map[string]string{
							"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
							"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
							"acr.microsoft.com/token.inputs":  "2wucoufm4eqegr6z5nmg00bvmwguubf86kfxk6yir9pw",
						},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "msi-acrpull.microsoft.com/v1beta1",
								Kind:               "AcrPullBinding",
								Name:               "binding",
								Controller:         ptr.To(true),
								BlockOwnerDeletion: ptr.To(true),
							},
						},
					},
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						".dockerconfigjson": []byte(`{"auths":{"DefaultACRServer":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
					},
				},
			},
		},
		{
			name: "out-of-date status updated for new token secret",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta1.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
				},
				Status: msiacrpullv1beta1.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: recentExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding-37d7ayn69u"}},
			},
			pullSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding-37d7ayn69u",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "2wucoufm4eqegr6z5nmg00bvmwguubf86kfxk6yir9pw",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "msi-acrpull.microsoft.com/v1beta1",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"DefaultACRServer":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			},
			output: &action{
				updatePullBindingStatus: &msiacrpullv1beta1.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
					Spec: msiacrpullv1beta1.AcrPullBindingSpec{
						ServiceAccountName: "delegate",
					},
					Status: msiacrpullv1beta1.AcrPullBindingStatus{
						LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
						TokenExpirationTime:  &metav1.Time{Time: longExpiry},
					},
				},
			},
		},
		{
			name: "everything up-to-date, do nothing",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta1.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
				},
				Status: msiacrpullv1beta1.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: longExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding-37d7ayn69u"}},
			},
			referencingServiceAccounts: []corev1.ServiceAccount{
				{
					ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding-37d7ayn69u"}},
				},
			},
			pullSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding-37d7ayn69u",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "2wucoufm4eqegr6z5nmg00bvmwguubf86kfxk6yir9pw",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "msi-acrpull.microsoft.com/v1beta1",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"DefaultACRServer":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			},
		},
		{
			name: "user changes bound service account, remove previous reference",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec:       msiacrpullv1beta1.AcrPullBindingSpec{},
				Status: msiacrpullv1beta1.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: longExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "default"},
				ImagePullSecrets: []corev1.LocalObjectReference{},
			},
			referencingServiceAccounts: []corev1.ServiceAccount{
				{
					ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding-37d7ayn69u"}},
				},
			},
			pullSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding-37d7ayn69u",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "2wucoufm4eqegr6z5nmg00bvmwguubf86kfxk6yir9pw",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "msi-acrpull.microsoft.com/v1beta1",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"DefaultACRServer":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			},
			output: &action{
				updateServiceAccount: &corev1.ServiceAccount{
					ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
					ImagePullSecrets: []corev1.LocalObjectReference{},
				},
			},
		},
		{
			name: "user changes ACR server, regenerate",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta1.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					AcrServer:          "somewhere.else.biz",
				},
				Status: msiacrpullv1beta1.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: longExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding-37d7ayn69u"}},
			},
			pullSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding-37d7ayn69u",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "2wucoufm4eqegr6z5nmg00bvmwguubf86kfxk6yir9pw",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "msi-acrpull.microsoft.com/v1beta1",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"DefaultACRServer":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			},
			registerTokenCall: func(mock *mock_authorizer.MockInterface) {
				mock.EXPECT().AcquireACRAccessToken(
					context.Background(),
					gomock.Eq(defaultManagedIdentityResourceID),
					gomock.Eq(""),
					gomock.Eq("somewhere.else.biz"),
					gomock.Eq("")).
					Return(otherToken, nil).
					Times(1)
			},
			output: &action{
				updateSecret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "acr-pull-binding-37d7ayn69u",
						Labels: map[string]string{
							"acr.microsoft.com/binding": "binding",
						},
						Annotations: map[string]string{
							"acr.microsoft.com/token.expiry":  otherExpiry.Format(time.RFC3339),
							"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
							"acr.microsoft.com/token.inputs":  "1zgwms3qm24vy8nn9xaxnmio6ux9exubtj2uged0qbjp",
						},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "msi-acrpull.microsoft.com/v1beta1",
								Kind:               "AcrPullBinding",
								Name:               "binding",
								Controller:         ptr.To(true),
								BlockOwnerDeletion: ptr.To(true),
							},
						},
					},
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						".dockerconfigjson": []byte(`{"auths":{"somewhere.else.biz":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYyNTc0NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.iwswC8pxfJVS_f5wIL5uLDKP6qQmqdrmJRr2I7pX7o8gdnA2e23WTXfdOPTBO2J6ez1hbu5rvWBGDfjTKC48buDDym44zIOlm59PON4dtJSjZXZOXu2xrhvO09wVLdY1Wg713jWowhAZXMnOQ-5ynxvIUnZ9f5MFY6H1r4OBlUTOhAb2rpxHDnP53-XYu-e1IkVmyoX8zyd00jTY6-YCZXkBDcXpynS1ziTLuqQ8RIDxz27zkPqgafV7rjuvYVJkkmlLWs8Sw_pdaCm6Nplb7FB7LnJKcN21DTvTP0skzztXQCreKMOoVaerexeR_qKGjdVimCDGIZmkUClnO4oo9A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXlOVGMwTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLml3c3dDOHB4ZkpWU19mNXdJTDV1TERLUDZxUW1xZHJtSlJyMkk3cFg3bzhnZG5BMmUyM1dUWGZkT1BUQk8ySjZlejFoYnU1cnZXQkdEZmpUS0M0OGJ1RER5bTQ0eklPbG01OVBPTjRkdEpTalpYWk9YdTJ4cmh2TzA5d1ZMZFkxV2c3MTNqV293aEFaWE1uT1EtNXlueHZJVW5aOWY1TUZZNkgxcjRPQmxVVE9oQWIycnB4SERuUDUzLVhZdS1lMUlrVm15b1g4enlkMDBqVFk2LVlDWlhrQkRjWHB5blMxemlUTHVxUThSSUR4ejI3emtQcWdhZlY3cmp1dllWSmtrbWxMV3M4U3dfcGRhQ202TnBsYjdGQjdMbkpLY04yMURUdlRQMHNrenp0WFFDcmVLTU9vVmFlcmV4ZVJfcUtHamRWaW1DREdJWm1rVUNsbk80b285QQ=="}}}`),
					},
				},
			},
		},
		{
			name: "user changes resource ID, regenerate",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta1.AcrPullBindingSpec{
					ServiceAccountName:        "delegate",
					AcrServer:                 "somewhere.else.biz",
					ManagedIdentityResourceID: "./whatever/identity//",
				},
				Status: msiacrpullv1beta1.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: longExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding-37d7ayn69u"}},
			},
			pullSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding-37d7ayn69u",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "1zgwms3qm24vy8nn9xaxnmio6ux9exubtj2uged0qbjp",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "msi-acrpull.microsoft.com/v1beta1",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"DefaultACRServer":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			},
			registerTokenCall: func(mock *mock_authorizer.MockInterface) {
				mock.EXPECT().AcquireACRAccessToken(
					context.Background(),
					gomock.Eq("whatever/identity"),
					gomock.Eq(""),
					gomock.Eq("somewhere.else.biz"),
					gomock.Eq("")).
					Return(otherToken, nil).
					Times(1)
			},
			output: &action{
				updateSecret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "acr-pull-binding-37d7ayn69u",
						Labels: map[string]string{
							"acr.microsoft.com/binding": "binding",
						},
						Annotations: map[string]string{
							"acr.microsoft.com/token.expiry":  otherExpiry.Format(time.RFC3339),
							"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
							"acr.microsoft.com/token.inputs":  "1heyo3x93ljuxr5x2cwq6i068hxgwnsiyzjfzpb3gai8",
						},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "msi-acrpull.microsoft.com/v1beta1",
								Kind:               "AcrPullBinding",
								Name:               "binding",
								Controller:         ptr.To(true),
								BlockOwnerDeletion: ptr.To(true),
							},
						},
					},
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						".dockerconfigjson": []byte(`{"auths":{"somewhere.else.biz":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYyNTc0NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.iwswC8pxfJVS_f5wIL5uLDKP6qQmqdrmJRr2I7pX7o8gdnA2e23WTXfdOPTBO2J6ez1hbu5rvWBGDfjTKC48buDDym44zIOlm59PON4dtJSjZXZOXu2xrhvO09wVLdY1Wg713jWowhAZXMnOQ-5ynxvIUnZ9f5MFY6H1r4OBlUTOhAb2rpxHDnP53-XYu-e1IkVmyoX8zyd00jTY6-YCZXkBDcXpynS1ziTLuqQ8RIDxz27zkPqgafV7rjuvYVJkkmlLWs8Sw_pdaCm6Nplb7FB7LnJKcN21DTvTP0skzztXQCreKMOoVaerexeR_qKGjdVimCDGIZmkUClnO4oo9A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXlOVGMwTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLml3c3dDOHB4ZkpWU19mNXdJTDV1TERLUDZxUW1xZHJtSlJyMkk3cFg3bzhnZG5BMmUyM1dUWGZkT1BUQk8ySjZlejFoYnU1cnZXQkdEZmpUS0M0OGJ1RER5bTQ0eklPbG01OVBPTjRkdEpTalpYWk9YdTJ4cmh2TzA5d1ZMZFkxV2c3MTNqV293aEFaWE1uT1EtNXlueHZJVW5aOWY1TUZZNkgxcjRPQmxVVE9oQWIycnB4SERuUDUzLVhZdS1lMUlrVm15b1g4enlkMDBqVFk2LVlDWlhrQkRjWHB5blMxemlUTHVxUThSSUR4ejI3emtQcWdhZlY3cmp1dllWSmtrbWxMV3M4U3dfcGRhQ202TnBsYjdGQjdMbkpLY04yMURUdlRQMHNrenp0WFFDcmVLTU9vVmFlcmV4ZVJfcUtHamRWaW1DREdJWm1rVUNsbk80b285QQ=="}}}`),
					},
				},
			},
		},
		{
			name: "user changes to use a client ID, regenerate",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta1.AcrPullBindingSpec{
					ServiceAccountName:      "delegate",
					AcrServer:               "somewhere.else.biz",
					ManagedIdentityClientID: "client-identity",
				},
				Status: msiacrpullv1beta1.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: longExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding-37d7ayn69u"}},
			},
			pullSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding-37d7ayn69u",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "1heyo3x93ljuxr5x2cwq6i068hxgwnsiyzjfzpb3gai8",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "msi-acrpull.microsoft.com/v1beta1",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"DefaultACRServer":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			},
			registerTokenCall: func(mock *mock_authorizer.MockInterface) {
				mock.EXPECT().AcquireACRAccessToken(
					context.Background(),
					gomock.Eq(defaultManagedIdentityResourceID),
					gomock.Eq("client-identity"),
					gomock.Eq("somewhere.else.biz"),
					gomock.Eq("")).
					Return(otherToken, nil).
					Times(1)
			},
			output: &action{
				updateSecret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "acr-pull-binding-37d7ayn69u",
						Labels: map[string]string{
							"acr.microsoft.com/binding": "binding",
						},
						Annotations: map[string]string{
							"acr.microsoft.com/token.expiry":  otherExpiry.Format(time.RFC3339),
							"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
							"acr.microsoft.com/token.inputs":  "2ly31qdswhqrgh1j0vbpmt2oopxt3sxbjhfsef4x942x",
						},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "msi-acrpull.microsoft.com/v1beta1",
								Kind:               "AcrPullBinding",
								Name:               "binding",
								Controller:         ptr.To(true),
								BlockOwnerDeletion: ptr.To(true),
							},
						},
					},
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						".dockerconfigjson": []byte(`{"auths":{"somewhere.else.biz":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYyNTc0NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.iwswC8pxfJVS_f5wIL5uLDKP6qQmqdrmJRr2I7pX7o8gdnA2e23WTXfdOPTBO2J6ez1hbu5rvWBGDfjTKC48buDDym44zIOlm59PON4dtJSjZXZOXu2xrhvO09wVLdY1Wg713jWowhAZXMnOQ-5ynxvIUnZ9f5MFY6H1r4OBlUTOhAb2rpxHDnP53-XYu-e1IkVmyoX8zyd00jTY6-YCZXkBDcXpynS1ziTLuqQ8RIDxz27zkPqgafV7rjuvYVJkkmlLWs8Sw_pdaCm6Nplb7FB7LnJKcN21DTvTP0skzztXQCreKMOoVaerexeR_qKGjdVimCDGIZmkUClnO4oo9A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXlOVGMwTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLml3c3dDOHB4ZkpWU19mNXdJTDV1TERLUDZxUW1xZHJtSlJyMkk3cFg3bzhnZG5BMmUyM1dUWGZkT1BUQk8ySjZlejFoYnU1cnZXQkdEZmpUS0M0OGJ1RER5bTQ0eklPbG01OVBPTjRkdEpTalpYWk9YdTJ4cmh2TzA5d1ZMZFkxV2c3MTNqV293aEFaWE1uT1EtNXlueHZJVW5aOWY1TUZZNkgxcjRPQmxVVE9oQWIycnB4SERuUDUzLVhZdS1lMUlrVm15b1g4enlkMDBqVFk2LVlDWlhrQkRjWHB5blMxemlUTHVxUThSSUR4ejI3emtQcWdhZlY3cmp1dllWSmtrbWxMV3M4U3dfcGRhQ202TnBsYjdGQjdMbkpLY04yMURUdlRQMHNrenp0WFFDcmVLTU9vVmFlcmV4ZVJfcUtHamRWaW1DREdJWm1rVUNsbk80b285QQ=="}}}`),
					},
				},
			},
		},
		{
			name: "binding deleted, clean up service account list",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "binding",
					Finalizers:        []string{"msi-acrpull.microsoft.com"},
					DeletionTimestamp: &metav1.Time{Time: fakeClock.Now().Add(-1 * time.Minute)},
				},
				Spec: msiacrpullv1beta1.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
				},
				Status: msiacrpullv1beta1.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: longExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding-37d7ayn69u"}},
			},
			pullSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding-37d7ayn69u",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "2wucoufm4eqegr6z5nmg00bvmwguubf86kfxk6yir9pw",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "msi-acrpull.microsoft.com/v1beta1",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"DefaultACRServer":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			},
			output: &action{
				updateServiceAccount: &corev1.ServiceAccount{
					ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
					ImagePullSecrets: []corev1.LocalObjectReference{},
				},
			},
		},
		{
			name: "binding deleted, service account cleaned up, delete secret",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "binding",
					Finalizers:        []string{"msi-acrpull.microsoft.com"},
					DeletionTimestamp: &metav1.Time{Time: fakeClock.Now().Add(-1 * time.Minute)},
				},
				Spec: msiacrpullv1beta1.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
				},
				Status: msiacrpullv1beta1.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: longExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{},
			},
			pullSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding-37d7ayn69u",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "2wucoufm4eqegr6z5nmg00bvmwguubf86kfxk6yir9pw",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "msi-acrpull.microsoft.com/v1beta1",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"DefaultACRServer":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			},
			output: &action{
				deleteSecret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "acr-pull-binding-37d7ayn69u",
						Labels: map[string]string{
							"acr.microsoft.com/binding": "binding",
						},
						Annotations: map[string]string{
							"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
							"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
							"acr.microsoft.com/token.inputs":  "2wucoufm4eqegr6z5nmg00bvmwguubf86kfxk6yir9pw",
						},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "msi-acrpull.microsoft.com/v1beta1",
								Kind:               "AcrPullBinding",
								Name:               "binding",
								Controller:         ptr.To(true),
								BlockOwnerDeletion: ptr.To(true),
							},
						},
					},
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						".dockerconfigjson": []byte(`{"auths":{"DefaultACRServer":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
					},
				},
			},
		},
		{
			name: "binding deleted, service account cleaned up, secret deleted, remove finalizer",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "binding",
					Finalizers:        []string{"msi-acrpull.microsoft.com"},
					DeletionTimestamp: &metav1.Time{Time: fakeClock.Now().Add(-1 * time.Minute)},
				},
				Spec: msiacrpullv1beta1.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
				},
				Status: msiacrpullv1beta1.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: longExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{},
			},
			pullSecret: nil,
			output: &action{
				updatePullBinding: &msiacrpullv1beta1.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "binding",
						Finalizers:        []string{},
						DeletionTimestamp: &metav1.Time{Time: fakeClock.Now().Add(-1 * time.Minute)},
					},
					Spec: msiacrpullv1beta1.AcrPullBindingSpec{
						ServiceAccountName: "delegate",
					},
					Status: msiacrpullv1beta1.AcrPullBindingStatus{
						LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
						TokenExpirationTime:  &metav1.Time{Time: longExpiry},
					},
				},
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			fakeAuth := mock_authorizer.NewMockInterface(mockCtrl)
			if testCase.registerTokenCall != nil {
				testCase.registerTokenCall(fakeAuth)
			}
			controller := &AcrPullBindingReconciler{
				Log:                              testr.NewWithOptions(t, testr.Options{Verbosity: 0}),
				Scheme:                           scheme.Scheme,
				Auth:                             fakeAuth,
				DefaultManagedIdentityResourceID: defaultManagedIdentityResourceID,
				DefaultACRServer:                 defaultACRServer,
				now:                              fakeClock.Now,
			}

			output := controller.reconcile(context.Background(), controller.Log, testCase.acrBinding, testCase.serviceAccount, testCase.pullSecret, testCase.referencingServiceAccounts)
			if diff := cmp.Diff(testCase.output, output, cmp.AllowUnexported(action{})); diff != "" {
				t.Errorf("-want, +got:\n%s", diff)
			}
		})
	}
}

func isValidName(input string) bool {
	return len(apimachineryvalidation.NameIsDNSSubdomain(input, false)) == 0
}

func FuzzPullSecretName(f *testing.F) {
	seeds := []string{
		"abc",
		"ebf8018b88187fa15444859cc3050ec7cb04ddc1ebf8018b88187fa15444859c",
		"ebf8018b88187fa15444859cc3050ec7cb04ddc1ebf.018b88187fa15444859c",
		"ebf8018b88187fa15444859cc3050ec7cb04ddc1ebf-018b88187fa15444859c",
		"ebf8018b8.187fa15444859cc3050ec7cb04.dc1ebf8018b8.187fa15444859c",
		"ebf8-18b8.187f-15444859-c3050ec7cb04.dc1e-f8018b8.187fa15444859c",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		output := pullSecretName(input)

		// Enforce that we produce a valid *corev1.Secret name, given a valid custom resource name. It happens that
		// both of these resources have the same requirement for naming:
		// CustomResources: https://github.com/kubernetes/kubernetes/blob/60c4c2b2521fb454ce69dee737e3eb91a25e0535/staging/src/k8s.io/apiextensions-apiserver/pkg/registry/customresource/validator.go#L53
		// Secrets: https://github.com/kubernetes/kubernetes/blob/60c4c2b2521fb454ce69dee737e3eb91a25e0535/pkg/apis/core/validation/validation.go#L282
		if isValidName(input) && !isValidName(output) {
			t.Errorf("input %q created invalid output %q", input, output)
		}
	})
}
