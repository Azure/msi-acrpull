package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	msiacrpullv1beta2 "github.com/Azure/msi-acrpull/api/v1beta2"
	"github.com/go-logr/logr/testr"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	authenticationv1 "k8s.io/api/authentication/v1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	testingclock "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
)

func Test_ACRPullBindingController_v1beta2_reconcile(t *testing.T) {
	if err := msiacrpullv1beta2.AddToScheme(scheme.Scheme); err != nil {
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

	recentTTL := 1 * time.Minute
	recentRefresh := fakeClock.Now().Add(time.Duration(-0.6 * float64(recentTTL))).UTC()
	recentExpiry := fakeClock.Now().Add(time.Duration(0.4 * float64(recentTTL))).UTC()
	// acquired the expiring token like so, and used to encode the auth JSON for the secret
	// expiringToken := getTestToken(t, fakeClock.Now, recentExpiry)

	for _, testCase := range []struct {
		name                       string
		acrBinding                 *msiacrpullv1beta2.AcrPullBinding
		serviceAccount             *corev1.ServiceAccount
		pullSecrets                []corev1.Secret
		referencingServiceAccounts []corev1.ServiceAccount

		tokenStub func(*testing.T, *msiacrpullv1beta2.AcrPullBinding, *corev1.ServiceAccount) (ServiceAccountTokenMinter, acrAudienceEntraTokenFetcher, acrAudienceEntraTokenExchanger)

		output *action[*msiacrpullv1beta2.AcrPullBinding]
	}{
		{
			name: "binding missing finalizer gets one",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding"},
			},
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				updatePullBinding: &msiacrpullv1beta2.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				},
			},
		},
		{
			name: "missing service account errors",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "missing",
				},
			},
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				updatePullBindingStatus: &msiacrpullv1beta2.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
					Spec: msiacrpullv1beta2.AcrPullBindingSpec{
						ServiceAccountName: "missing",
					},
					Status: msiacrpullv1beta2.AcrPullBindingStatus{
						Error: `service account "missing" not found`,
					},
				},
			},
		},
		{
			name: "managed identity resource ID binding missing pull credential mints a new one",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "registry.azurecr.io",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
							ResourceID: "resource",
						},
					},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
			},
			pullSecrets: nil,
			tokenStub:   managedIdentityValidatingTokenStub(futureToken, nil),
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				createSecret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "acr-pull-binding",
						Labels: map[string]string{
							"acr.microsoft.com/binding": "binding",
						},
						Annotations: map[string]string{
							"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
							"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
							"acr.microsoft.com/token.inputs":  "2goxvjvcjze0v96ooojjo7okj10q3qo5rtq9tgckauh",
						},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "acrpull.microsoft.com/v1beta2",
								Kind:               "AcrPullBinding",
								Name:               "binding",
								Controller:         ptr.To(true),
								BlockOwnerDeletion: ptr.To(true),
							},
						},
					},
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
					},
				},
			},
		},
		{
			name: "managed identity client ID binding missing pull credential mints a new one",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "registry.azurecr.io",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
							ClientID: "client-id",
						},
					},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
			},
			pullSecrets: nil,
			tokenStub:   managedIdentityValidatingTokenStub(futureToken, nil),
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				createSecret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "acr-pull-binding",
						Labels: map[string]string{
							"acr.microsoft.com/binding": "binding",
						},
						Annotations: map[string]string{
							"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
							"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
							"acr.microsoft.com/token.inputs":  "bznn8knczhrdktghbm88h4ock013v94i8e8cslwlrob",
						},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "acrpull.microsoft.com/v1beta2",
								Kind:               "AcrPullBinding",
								Name:               "binding",
								Controller:         ptr.To(true),
								BlockOwnerDeletion: ptr.To(true),
							},
						},
					},
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
					},
				},
			},
		},
		{
			name: "workload identity binding missing pull credential mints a new one",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "registry.azurecr.io",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						WorkloadIdentity: &msiacrpullv1beta2.WorkloadIdentityAuth{
							ServiceAccountName: "delegate",
						},
					},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "delegate",
					Annotations: map[string]string{
						"azure.workload.identity/tenant-id": "tenant-id",
						"azure.workload.identity/client-id": "client-id",
					},
				},
			},
			pullSecrets: nil,
			tokenStub:   workloadIdentityValidatingTokenStub(futureToken, nil),
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				createSecret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "acr-pull-binding",
						Labels: map[string]string{
							"acr.microsoft.com/binding": "binding",
						},
						Annotations: map[string]string{
							"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
							"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
							"acr.microsoft.com/token.inputs":  "zrlombgy4mz11lkl9yxxi5n5sibq3cknbiekmkf7aju",
						},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "acrpull.microsoft.com/v1beta2",
								Kind:               "AcrPullBinding",
								Name:               "binding",
								Controller:         ptr.To(true),
								BlockOwnerDeletion: ptr.To(true),
							},
						},
					},
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
					},
				},
			},
		},
		{
			name: "workload identity binding with literal identifiers missing pull credential mints a new one",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "registry.azurecr.io",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						WorkloadIdentity: &msiacrpullv1beta2.WorkloadIdentityAuth{
							ServiceAccountName: "delegate",
							ClientID:           "client-id",
							TenantID:           "tenant-id",
						},
					},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "delegate",
					Annotations: map[string]string{
						"azure.workload.identity/tenant-id": "other-tenant-id",
						"azure.workload.identity/client-id": "other-client-id",
					},
				},
			},
			pullSecrets: nil,
			tokenStub:   workloadIdentityLiteralValidatingTokenStub(futureToken, nil),
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				createSecret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "acr-pull-binding",
						Labels: map[string]string{
							"acr.microsoft.com/binding": "binding",
						},
						Annotations: map[string]string{
							"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
							"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
							"acr.microsoft.com/token.inputs":  "zrlombgy4mz11lkl9yxxi5n5sibq3cknbiekmkf7aju",
						},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "acrpull.microsoft.com/v1beta2",
								Kind:               "AcrPullBinding",
								Name:               "binding",
								Controller:         ptr.To(true),
								BlockOwnerDeletion: ptr.To(true),
							},
						},
					},
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
					},
				},
			},
		},
		{
			name: "workload identity binding referring to service account without workload identity errors",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "registry.azurecr.io",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						WorkloadIdentity: &msiacrpullv1beta2.WorkloadIdentityAuth{
							ServiceAccountName: "delegate",
						},
					},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
			},
			pullSecrets: nil,
			tokenStub:   workloadIdentityValidatingTokenStub(futureToken, nil),
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				updatePullBindingStatus: &msiacrpullv1beta2.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
					Spec: msiacrpullv1beta2.AcrPullBindingSpec{
						ServiceAccountName: "delegate",
						ACR: msiacrpullv1beta2.AcrConfiguration{
							Server:      "registry.azurecr.io",
							Scope:       "repository:testing:pull,push",
							Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
						},
						Auth: msiacrpullv1beta2.AuthenticationMethod{
							WorkloadIdentity: &msiacrpullv1beta2.WorkloadIdentityAuth{
								ServiceAccountName: "delegate",
							},
						},
					},
					Status: msiacrpullv1beta2.AcrPullBindingStatus{
						Error: "service account delegate missing azure.workload.identity/client-id annotation",
					},
				},
			},
		},
		{
			name: "failure getting pull credential exposed",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "registry.azurecr.io",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
							ClientID: "client-id",
						},
					},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
			},
			pullSecrets: nil,
			tokenStub:   managedIdentityValidatingTokenStub(azcore.AccessToken{}, errors.New("oops")),
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				updatePullBindingStatus: &msiacrpullv1beta2.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
					Spec: msiacrpullv1beta2.AcrPullBindingSpec{
						ServiceAccountName: "delegate",
						ACR: msiacrpullv1beta2.AcrConfiguration{
							Server:      "registry.azurecr.io",
							Scope:       "repository:testing:pull,push",
							Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
						},
						Auth: msiacrpullv1beta2.AuthenticationMethod{
							ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
								ClientID: "client-id",
							},
						},
					},
					Status: msiacrpullv1beta2.AcrPullBindingStatus{
						Error: `failed to retrieve ACR audience Entra token: oops`,
					},
				},
			},
		},
		{
			name: "binding with pull credential updates the service account",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "registry.azurecr.io",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
							ClientID: "client-id",
						},
					},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
			},
			pullSecrets: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "bznn8knczhrdktghbm88h4ock013v94i8e8cslwlrob",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "acrpull.microsoft.com/v1beta2",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			}},
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				updateServiceAccount: &corev1.ServiceAccount{
					ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}},
				},
			},
		},
		{
			name: "binding with pull credential updates the service account honoring ordering requirements",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "registry.azurecr.io",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
							ClientID: "client-id",
						},
					},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "previous-msi-acrpull-secret"}},
			},
			pullSecrets: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "bznn8knczhrdktghbm88h4ock013v94i8e8cslwlrob",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "acrpull.microsoft.com/v1beta2",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			}},
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				updateServiceAccount: &corev1.ServiceAccount{
					ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}, {Name: "previous-msi-acrpull-secret"}},
				},
			},
		},
		{
			name: "binding with pull credential recorded on service account updates binding status",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "registry.azurecr.io",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
							ClientID: "client-id",
						},
					},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}},
			},
			pullSecrets: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "bznn8knczhrdktghbm88h4ock013v94i8e8cslwlrob",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "acrpull.microsoft.com/v1beta2",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			}},
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				updatePullBindingStatus: &msiacrpullv1beta2.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
					Spec: msiacrpullv1beta2.AcrPullBindingSpec{
						ServiceAccountName: "delegate",
						ACR: msiacrpullv1beta2.AcrConfiguration{
							Server:      "registry.azurecr.io",
							Scope:       "repository:testing:pull,push",
							Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
						},
						Auth: msiacrpullv1beta2.AuthenticationMethod{
							ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
								ClientID: "client-id",
							},
						},
					},
					Status: msiacrpullv1beta2.AcrPullBindingStatus{
						LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
						TokenExpirationTime:  &metav1.Time{Time: longExpiry},
					},
				},
			},
		},
		{
			name: "expiring pull credential mints a new one",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "registry.azurecr.io",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
							ClientID: "client-id",
						},
					},
				},
				Status: msiacrpullv1beta2.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: recentRefresh},
					TokenExpirationTime:  &metav1.Time{Time: recentExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}},
			},
			pullSecrets: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  recentExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": recentRefresh.Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "bznn8knczhrdktghbm88h4ock013v94i8e8cslwlrob",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "acrpull.microsoft.com/v1beta2",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYyMTQzMDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.pt3Ra4QKcq7mHX3Qp9-0vzpzQKooPJmviQLWazhlcgHjtnf-QL3ZZYVy1F06ExmznYbtU1ADGOBuhtn94ORezYZ5Dg3eSS5hSpuSnJdpGQlkzLxsfyFUszKvKraqQ72hcRZ5kYkRd9dMT-yGphMoIqP3crfrzFR4ZIwf0JBMxiS_iNIvi7RHpg0lBLDZdP739lNQ6oY-O76H_SuYbgJ7HP0nssVy0DlQF6HT9X6Qq1gTCxuK28Juo2yDeTSaagjihgXeUc4zH2cMKz6f5deoIr3i7BNMuXVHOyXeEcShohHmfUFAAmr_LiotZsTeEXVaMkaoRFlCBb2bv2lM9PzFyw","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXlNVFF6TURVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLnB0M1JhNFFLY3E3bUhYM1FwOS0wdnpwelFLb29QSm12aVFMV2F6aGxjZ0hqdG5mLVFMM1paWVZ5MUYwNkV4bXpuWWJ0VTFBREdPQnVodG45NE9SZXpZWjVEZzNlU1M1aFNwdVNuSmRwR1Fsa3pMeHNmeUZVc3pLdktyYXFRNzJoY1JaNWtZa1JkOWRNVC15R3BoTW9JcVAzY3JmcnpGUjRaSXdmMEpCTXhpU19pTkl2aTdSSHBnMGxCTERaZFA3MzlsTlE2b1ktTzc2SF9TdVliZ0o3SFAwbnNzVnkwRGxRRjZIVDlYNlFxMWdUQ3h1SzI4SnVvMnlEZVRTYWFnamloZ1hlVWM0ekgyY01LejZmNWRlb0lyM2k3Qk5NdVhWSE95WGVFY1Nob2hIbWZVRkFBbXJfTGlvdFpzVGVFWFZhTWthb1JGbENCYjJidjJsTTlQekZ5dw=="}}}`),
				},
			}},
			tokenStub: managedIdentityValidatingTokenStub(futureToken, nil),
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				updateSecret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "acr-pull-binding",
						Labels: map[string]string{
							"acr.microsoft.com/binding": "binding",
						},
						Annotations: map[string]string{
							"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
							"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
							"acr.microsoft.com/token.inputs":  "bznn8knczhrdktghbm88h4ock013v94i8e8cslwlrob",
						},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "acrpull.microsoft.com/v1beta2",
								Kind:               "AcrPullBinding",
								Name:               "binding",
								Controller:         ptr.To(true),
								BlockOwnerDeletion: ptr.To(true),
							},
						},
					},
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
					},
				},
			},
		},
		{
			name: "out-of-date status updated for new token secret",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "registry.azurecr.io",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
							ClientID: "client-id",
						},
					},
				},
				Status: msiacrpullv1beta2.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: recentExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}},
			},
			pullSecrets: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "bznn8knczhrdktghbm88h4ock013v94i8e8cslwlrob",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "acrpull.microsoft.com/v1beta2",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			}},
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				updatePullBindingStatus: &msiacrpullv1beta2.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
					Spec: msiacrpullv1beta2.AcrPullBindingSpec{
						ServiceAccountName: "delegate",
						ACR: msiacrpullv1beta2.AcrConfiguration{
							Server:      "registry.azurecr.io",
							Scope:       "repository:testing:pull,push",
							Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
						},
						Auth: msiacrpullv1beta2.AuthenticationMethod{
							ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
								ClientID: "client-id",
							},
						},
					},
					Status: msiacrpullv1beta2.AcrPullBindingStatus{
						LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
						TokenExpirationTime:  &metav1.Time{Time: longExpiry},
					},
				},
			},
		},
		{
			name: "everything up-to-date, remove extraneous pull secret reference from service account",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "registry.azurecr.io",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
							ClientID: "client-id",
						},
					},
				},
				Status: msiacrpullv1beta2.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: longExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}, {Name: "acr-pull-binding-other"}},
			},
			referencingServiceAccounts: []corev1.ServiceAccount{
				{
					ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}, {Name: "acr-pull-binding-other"}},
				},
			},
			pullSecrets: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "bznn8knczhrdktghbm88h4ock013v94i8e8cslwlrob",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "acrpull.microsoft.com/v1beta2",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			}, {
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding-other",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
				},
			}},
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				updateServiceAccount: &corev1.ServiceAccount{
					ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}},
				},
			},
		},
		{
			name: "everything up-to-date, remove extraneous pull secret",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "registry.azurecr.io",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
							ClientID: "client-id",
						},
					},
				},
				Status: msiacrpullv1beta2.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: longExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}},
			},
			referencingServiceAccounts: []corev1.ServiceAccount{
				{
					ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}},
				},
			},
			pullSecrets: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "bznn8knczhrdktghbm88h4ock013v94i8e8cslwlrob",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "acrpull.microsoft.com/v1beta2",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			}, {
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding-other",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
				},
			}},
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				deleteSecret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "acr-pull-binding-other",
						Labels: map[string]string{
							"acr.microsoft.com/binding": "binding",
						},
					},
				},
			},
		},
		{
			name: "everything up-to-date, do nothing",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "registry.azurecr.io",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
							ClientID: "client-id",
						},
					},
				},
				Status: msiacrpullv1beta2.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: longExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}},
			},
			referencingServiceAccounts: []corev1.ServiceAccount{
				{
					ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}},
				},
			},
			pullSecrets: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "bznn8knczhrdktghbm88h4ock013v94i8e8cslwlrob",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "acrpull.microsoft.com/v1beta2",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			}},
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				noop: &msiacrpullv1beta2.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
					Spec: msiacrpullv1beta2.AcrPullBindingSpec{
						ServiceAccountName: "delegate",
						ACR: msiacrpullv1beta2.AcrConfiguration{
							Server:      "registry.azurecr.io",
							Scope:       "repository:testing:pull,push",
							Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
						},
						Auth: msiacrpullv1beta2.AuthenticationMethod{
							ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
								ClientID: "client-id",
							},
						},
					},
					Status: msiacrpullv1beta2.AcrPullBindingStatus{
						LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
						TokenExpirationTime:  &metav1.Time{Time: longExpiry},
					},
				},
			},
		},
		{
			name: "user changes bound service account, remove previous reference",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec:       msiacrpullv1beta2.AcrPullBindingSpec{},
				Status: msiacrpullv1beta2.AcrPullBindingStatus{
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
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}},
				},
			},
			pullSecrets: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "bznn8knczhrdktghbm88h4ock013v94i8e8cslwlrob",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "acrpull.microsoft.com/v1beta2",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			}},
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				updateServiceAccount: &corev1.ServiceAccount{
					ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
					ImagePullSecrets: []corev1.LocalObjectReference{},
				},
			},
		},
		{
			name: "user changes bound service account during extraneous pull secret cleanup, remove all previous references",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec:       msiacrpullv1beta2.AcrPullBindingSpec{},
				Status: msiacrpullv1beta2.AcrPullBindingStatus{
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
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}, {Name: "acr-pull-binding-previous"}, {Name: "extraneous"}},
				},
			},
			pullSecrets: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "bznn8knczhrdktghbm88h4ock013v94i8e8cslwlrob",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "acrpull.microsoft.com/v1beta2",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			}, {
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding-previous",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
				},
			}},
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				updateServiceAccount: &corev1.ServiceAccount{
					ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "extraneous"}},
				},
			},
		},
		{
			name: "user changes ACR server, regenerate",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "somewhere.else.biz",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
							ClientID: "client-id",
						},
					},
				},
				Status: msiacrpullv1beta2.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: longExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}},
			},
			pullSecrets: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "bznn8knczhrdktghbm88h4ock013v94i8e8cslwlrob",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "acrpull.microsoft.com/v1beta2",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			}},
			tokenStub: managedIdentityValidatingTokenStub(otherToken, nil),
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				updateSecret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "acr-pull-binding",
						Labels: map[string]string{
							"acr.microsoft.com/binding": "binding",
						},
						Annotations: map[string]string{
							"acr.microsoft.com/token.expiry":  otherExpiry.Format(time.RFC3339),
							"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
							"acr.microsoft.com/token.inputs":  "254f0yg45bo7c4fu7ku7bhz2tdsd3rkpnbq2rjza2ymp",
						},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "acrpull.microsoft.com/v1beta2",
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
			name: "user changes client ID, regenerate",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "somewhere.else.biz",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
							ClientID: "other-client-id",
						},
					},
				},
				Status: msiacrpullv1beta2.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: longExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}},
			},
			pullSecrets: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "254f0yg45bo7c4fu7ku7bhz2tdsd3rkpnbq2rjza2ymp",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "acrpull.microsoft.com/v1beta2",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"somewhere.else.biz":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			}},
			tokenStub: managedIdentityValidatingTokenStub(otherToken, nil),
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				updateSecret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "acr-pull-binding",
						Labels: map[string]string{
							"acr.microsoft.com/binding": "binding",
						},
						Annotations: map[string]string{
							"acr.microsoft.com/token.expiry":  otherExpiry.Format(time.RFC3339),
							"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
							"acr.microsoft.com/token.inputs":  "a837crqqjnf2hg2d3qdewol2n47pn9am070tm7z9ug6",
						},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "acrpull.microsoft.com/v1beta2",
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
			name: "user changes to use a resource ID, regenerate",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding", Finalizers: []string{"msi-acrpull.microsoft.com"}},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "somewhere.else.biz",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
							ResourceID: "/some/resource",
						},
					},
				},
				Status: msiacrpullv1beta2.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: longExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}},
			},
			pullSecrets: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "a837crqqjnf2hg2d3qdewol2n47pn9am070tm7z9ug6",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "acrpull.microsoft.com/v1beta2",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"somewhere.else.biz":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			}},
			tokenStub: managedIdentityValidatingTokenStub(otherToken, nil),
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				updateSecret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "acr-pull-binding",
						Labels: map[string]string{
							"acr.microsoft.com/binding": "binding",
						},
						Annotations: map[string]string{
							"acr.microsoft.com/token.expiry":  otherExpiry.Format(time.RFC3339),
							"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
							"acr.microsoft.com/token.inputs":  "28xhymf4t5fcjg5f4mj62mk2dhsmafnogkvz5p3dyqs1",
						},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "acrpull.microsoft.com/v1beta2",
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
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "binding",
					Finalizers:        []string{"msi-acrpull.microsoft.com"},
					DeletionTimestamp: &metav1.Time{Time: fakeClock.Now().Add(-1 * time.Minute)},
				},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "somewhere.else.biz",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
							ClientID: "other-client-id",
						},
					},
				},
				Status: msiacrpullv1beta2.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: longExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding"}},
			},
			pullSecrets: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "bznn8knczhrdktghbm88h4ock013v94i8e8cslwlrob",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "acrpull.microsoft.com/v1beta2",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			}},
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				updateServiceAccount: &corev1.ServiceAccount{
					ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
					ImagePullSecrets: []corev1.LocalObjectReference{},
				},
			},
		},
		{
			name: "binding deleted, service account cleaned up, delete secret",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "binding",
					Finalizers:        []string{"msi-acrpull.microsoft.com"},
					DeletionTimestamp: &metav1.Time{Time: fakeClock.Now().Add(-1 * time.Minute)},
				},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "somewhere.else.biz",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
							ClientID: "other-client-id",
						},
					},
				},
				Status: msiacrpullv1beta2.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: longExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{},
			},
			pullSecrets: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "acr-pull-binding",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
					Annotations: map[string]string{
						"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
						"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
						"acr.microsoft.com/token.inputs":  "bznn8knczhrdktghbm88h4ock013v94i8e8cslwlrob",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "acrpull.microsoft.com/v1beta2",
							Kind:               "AcrPullBinding",
							Name:               "binding",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
				},
			}},
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				deleteSecret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "acr-pull-binding",
						Labels: map[string]string{
							"acr.microsoft.com/binding": "binding",
						},
						Annotations: map[string]string{
							"acr.microsoft.com/token.expiry":  longExpiry.Format(time.RFC3339),
							"acr.microsoft.com/token.refresh": fakeClock.Now().Format(time.RFC3339),
							"acr.microsoft.com/token.inputs":  "bznn8knczhrdktghbm88h4ock013v94i8e8cslwlrob",
						},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "acrpull.microsoft.com/v1beta2",
								Kind:               "AcrPullBinding",
								Name:               "binding",
								Controller:         ptr.To(true),
								BlockOwnerDeletion: ptr.To(true),
							},
						},
					},
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						".dockerconfigjson": []byte(`{"auths":{"registry.azurecr.io":{"username":"00000000-0000-0000-0000-000000000000","password":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LmF6dXJlY3IuaW8iLCJleHAiOjExMzYzMDA2NDUsImdyYW50X3R5cGUiOiJyZWZyZXNoX3Rva2VuIiwiaWF0IjoxMTM2MDQxNDQ1LCJpc3MiOiJBenVyZSBDb250YWluZXIgUmVnaXN0cnkiLCJqdGkiOiJiYjhkNmQzZC1jN2IwLTRmOTYtYTM5MC04NzM4ZjczMGU4YzYiLCJuYmYiOjExMzYxMjc4NDUsInBlcm1pc3Npb25zIjp7ImFjdGlvbnMiOlsicmVhZCJdfSwidmVyc2lvbiI6MX0.lb8wJOjWSmpVBX-qf0VTjRTKcSiPsqDAe_g-Fow_3LHcqXUyfRspjmFmH9YtaFN3TsA72givXOBE_UQSj2i1CPshvXVfpGuJRPssy_olq1uzfr2L8w6AL1jwM96gCP3e2Od5YT8p6Dbg4RDoBy5xz1zHluoUH2-4jiCh81bRzyAjQGZmKf1MQygLVHHuCjLlijpdw2wHp5nB4m27Yi5z5rrgLzcvXQnSEGIj2t0BY_AuNRbffEFCCFHeDlu6ud1F-Ak35ljIWhkJumP3Zud-rPdIc1YeCQCSGT2-yk4epVX_N4UPsk3hc6XeZxC4ctu9UX9mqfSNe5ZZlO6dtt963A","email":"msi-acrpull@azurecr.io","auth":"MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoZFdRaU9pSjBaWE4wTG1GNmRYSmxZM0l1YVc4aUxDSmxlSEFpT2pFeE16WXpNREEyTkRVc0ltZHlZVzUwWDNSNWNHVWlPaUp5WldaeVpYTm9YM1J2YTJWdUlpd2lhV0YwSWpveE1UTTJNRFF4TkRRMUxDSnBjM01pT2lKQmVuVnlaU0JEYjI1MFlXbHVaWElnVW1WbmFYTjBjbmtpTENKcWRHa2lPaUppWWpoa05tUXpaQzFqTjJJd0xUUm1PVFl0WVRNNU1DMDROek00Wmpjek1HVTRZellpTENKdVltWWlPakV4TXpZeE1qYzRORFVzSW5CbGNtMXBjM05wYjI1eklqcDdJbUZqZEdsdmJuTWlPbHNpY21WaFpDSmRmU3dpZG1WeWMybHZiaUk2TVgwLmxiOHdKT2pXU21wVkJYLXFmMFZUalJUS2NTaVBzcURBZV9nLUZvd18zTEhjcVhVeWZSc3BqbUZtSDlZdGFGTjNUc0E3MmdpdlhPQkVfVVFTajJpMUNQc2h2WFZmcEd1SlJQc3N5X29scTF1emZyMkw4dzZBTDFqd005NmdDUDNlMk9kNVlUOHA2RGJnNFJEb0J5NXh6MXpIbHVvVUgyLTRqaUNoODFiUnp5QWpRR1ptS2YxTVF5Z0xWSEh1Q2pMbGlqcGR3MndIcDVuQjRtMjdZaTV6NXJyZ0x6Y3ZYUW5TRUdJajJ0MEJZX0F1TlJiZmZFRkNDRkhlRGx1NnVkMUYtQWszNWxqSVdoa0p1bVAzWnVkLXJQZEljMVllQ1FDU0dUMi15azRlcFZYX040VVBzazNoYzZYZVp4QzRjdHU5VVg5bXFmU05lNVpabE82ZHR0OTYzQQ=="}}}`),
					},
				},
			},
		},
		{
			name: "binding deleted, service account cleaned up, secret deleted, remove finalizer",
			acrBinding: &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns", Name: "binding",
					Finalizers:        []string{"msi-acrpull.microsoft.com"},
					DeletionTimestamp: &metav1.Time{Time: fakeClock.Now().Add(-1 * time.Minute)},
				},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ServiceAccountName: "delegate",
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      "somewhere.else.biz",
						Scope:       "repository:testing:pull,push",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
							ClientID: "other-client-id",
						},
					},
				},
				Status: msiacrpullv1beta2.AcrPullBindingStatus{
					LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
					TokenExpirationTime:  &metav1.Time{Time: longExpiry},
				},
			},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Namespace: "ns", Name: "delegate"},
				ImagePullSecrets: []corev1.LocalObjectReference{},
			},
			pullSecrets: nil,
			output: &action[*msiacrpullv1beta2.AcrPullBinding]{
				updatePullBinding: &msiacrpullv1beta2.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns", Name: "binding",
						Finalizers:        []string{},
						DeletionTimestamp: &metav1.Time{Time: fakeClock.Now().Add(-1 * time.Minute)},
					},
					Spec: msiacrpullv1beta2.AcrPullBindingSpec{
						ServiceAccountName: "delegate",
						ACR: msiacrpullv1beta2.AcrConfiguration{
							Server:      "somewhere.else.biz",
							Scope:       "repository:testing:pull,push",
							Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
						},
						Auth: msiacrpullv1beta2.AuthenticationMethod{
							ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
								ClientID: "other-client-id",
							},
						},
					},
					Status: msiacrpullv1beta2.AcrPullBindingStatus{
						LastTokenRefreshTime: &metav1.Time{Time: fakeClock.Now()},
						TokenExpirationTime:  &metav1.Time{Time: longExpiry},
					},
				},
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			logger := testr.NewWithOptions(t, testr.Options{Verbosity: 0})
			if testCase.tokenStub == nil {
				testCase.tokenStub = noopTokenStub()
			}
			createToken, fetchACRAudienceEntraToken, exchangeACRAudienceEntraTokenForAcrToken := testCase.tokenStub(t, testCase.acrBinding, testCase.serviceAccount)
			controller := NewV1beta2Reconciler(&V1beta2ReconcilerOpts{
				CoreOpts: CoreOpts{
					Logger: logger,
					Scheme: scheme.Scheme,
					now:    fakeClock.Now,
				},
				mintToken:                                createToken,
				fetchACRAudienceEntraToken:               fetchACRAudienceEntraToken,
				exchangeACRAudienceEntraTokenForAcrToken: exchangeACRAudienceEntraTokenForAcrToken,
				TTLRotationFraction:                      0.5,
			})

			output := controller.reconcile(context.Background(), logger, testCase.acrBinding, testCase.serviceAccount, testCase.pullSecrets, testCase.referencingServiceAccounts)
			if diff := cmp.Diff(testCase.output, output, cmp.AllowUnexported(action[*msiacrpullv1beta2.AcrPullBinding]{})); diff != "" {
				t.Errorf("-want, +got:\n%s", diff)
			}
		})
	}
}

func noopTokenStub() func(*testing.T, *msiacrpullv1beta2.AcrPullBinding, *corev1.ServiceAccount) (ServiceAccountTokenMinter, acrAudienceEntraTokenFetcher, acrAudienceEntraTokenExchanger) {
	return func(t *testing.T, binding *msiacrpullv1beta2.AcrPullBinding, serviceAccount *corev1.ServiceAccount) (ServiceAccountTokenMinter, acrAudienceEntraTokenFetcher, acrAudienceEntraTokenExchanger) {
		return func(ctx context.Context, serviceAccountNamespace, serviceAccountName string) (*authenticationv1.TokenRequest, error) {
				return nil, errors.New("unexpected call to SA token request")
			}, func(ctx context.Context, spec msiacrpullv1beta2.AcrPullBindingSpec, tenantId, clientId, serviceAccountToken string) (azcore.AccessToken, error) {
				return azcore.AccessToken{}, errors.New("unexpected call to ACR audience Entra token request")
			}, func(ctx context.Context, acrAudienceEntraToken azcore.AccessToken, spec msiacrpullv1beta2.AcrConfiguration) (azcore.AccessToken, error) {
				return azcore.AccessToken{}, errors.New("unexpected call to ACR token exchange")
			}
	}
}

func managedIdentityValidatingTokenStub(output azcore.AccessToken, outputError error) func(*testing.T, *msiacrpullv1beta2.AcrPullBinding, *corev1.ServiceAccount) (ServiceAccountTokenMinter, acrAudienceEntraTokenFetcher, acrAudienceEntraTokenExchanger) {
	return func(t *testing.T, binding *msiacrpullv1beta2.AcrPullBinding, serviceAccount *corev1.ServiceAccount) (ServiceAccountTokenMinter, acrAudienceEntraTokenFetcher, acrAudienceEntraTokenExchanger) {
		return func(ctx context.Context, serviceAccountNamespace, serviceAccountName string) (*authenticationv1.TokenRequest, error) {
				return nil, errors.New("unexpected call to SA token request for managed identity")
			}, func(ctx context.Context, spec msiacrpullv1beta2.AcrPullBindingSpec, tenantId, clientId, serviceAccountToken string) (azcore.AccessToken, error) {
				assert.Empty(t, cmp.Diff(spec, binding.Spec), "ACR audience Entra token request binding spec mismatch")
				assert.Empty(t, serviceAccount.Annotations["azure.workload.identity/tenant-id"], "ACR audience Entra token request unexpected tenant id")
				assert.Empty(t, serviceAccount.Annotations["azure.workload.identity/client-id"], "ACR audience Entra token request unexpected client id")
				assert.Empty(t, serviceAccountToken, "ACR audience Entra token request unexpected service account token")
				return azcore.AccessToken{Token: "fake-arm-token"}, outputError
			}, func(ctx context.Context, acrAudienceEntraToken azcore.AccessToken, spec msiacrpullv1beta2.AcrConfiguration) (azcore.AccessToken, error) {
				assert.Empty(t, cmp.Diff(spec, binding.Spec.ACR), "ACR token exchange binding ACR spec mismatch")
				assert.Equal(t, "fake-arm-token", acrAudienceEntraToken.Token, "ACR token exchange ACR audience Entra token mismatch")
				return output, outputError
			}
	}
}

func workloadIdentityValidatingTokenStub(output azcore.AccessToken, outputError error) func(*testing.T, *msiacrpullv1beta2.AcrPullBinding, *corev1.ServiceAccount) (ServiceAccountTokenMinter, acrAudienceEntraTokenFetcher, acrAudienceEntraTokenExchanger) {
	return func(t *testing.T, binding *msiacrpullv1beta2.AcrPullBinding, serviceAccount *corev1.ServiceAccount) (ServiceAccountTokenMinter, acrAudienceEntraTokenFetcher, acrAudienceEntraTokenExchanger) {
		return func(ctx context.Context, serviceAccountNamespace, serviceAccountName string) (*authenticationv1.TokenRequest, error) {
				assert.Equal(t, serviceAccount.Namespace, serviceAccountNamespace, "token request service account namespace doesn't match service account object namespace")
				assert.Equal(t, serviceAccount.Name, serviceAccountName, "token request service account name doesn't match service account object name")
				assert.Equal(t, binding.Namespace, serviceAccountNamespace, "token request service account namespace doesn't match binding")
				assert.Equal(t, binding.Spec.Auth.WorkloadIdentity.ServiceAccountName, serviceAccountName, "token request service account name doesn't match service account configured in binding")
				return &authenticationv1.TokenRequest{
					Status: authenticationv1.TokenRequestStatus{
						Token: "fake-sa-token",
					},
				}, nil
			}, func(ctx context.Context, spec msiacrpullv1beta2.AcrPullBindingSpec, tenantId, clientId, serviceAccountToken string) (azcore.AccessToken, error) {
				assert.Empty(t, cmp.Diff(spec, binding.Spec), "ACR audience Entra token request binding spec mismatch")
				assert.Equal(t, serviceAccount.Annotations["azure.workload.identity/tenant-id"], tenantId, "ACR audience Entra token request tenant id mismatch")
				assert.Equal(t, serviceAccount.Annotations["azure.workload.identity/client-id"], clientId, "ACR audience Entra token request client id mismatch")
				assert.Equal(t, "fake-sa-token", serviceAccountToken, "ACR audience Entra token request service account token mismatch")
				return azcore.AccessToken{Token: "fake-arm-token"}, outputError
			}, func(ctx context.Context, acrAudienceEntraToken azcore.AccessToken, spec msiacrpullv1beta2.AcrConfiguration) (azcore.AccessToken, error) {
				assert.Empty(t, cmp.Diff(spec, binding.Spec.ACR), "ACR token exchange binding ACR spec mismatch")
				assert.Equal(t, "fake-arm-token", acrAudienceEntraToken.Token, "ACR token exchange ACR audience Entra token mismatch")
				return output, outputError
			}
	}
}

func workloadIdentityLiteralValidatingTokenStub(output azcore.AccessToken, outputError error) func(*testing.T, *msiacrpullv1beta2.AcrPullBinding, *corev1.ServiceAccount) (ServiceAccountTokenMinter, acrAudienceEntraTokenFetcher, acrAudienceEntraTokenExchanger) {
	return func(t *testing.T, binding *msiacrpullv1beta2.AcrPullBinding, serviceAccount *corev1.ServiceAccount) (ServiceAccountTokenMinter, acrAudienceEntraTokenFetcher, acrAudienceEntraTokenExchanger) {
		return func(ctx context.Context, serviceAccountNamespace, serviceAccountName string) (*authenticationv1.TokenRequest, error) {
				assert.Equal(t, serviceAccount.Namespace, serviceAccountNamespace, "token request service account namespace doesn't match service account object namespace")
				assert.Equal(t, serviceAccount.Name, serviceAccountName, "token request service account name doesn't match service account object name")
				assert.Equal(t, binding.Namespace, serviceAccountNamespace, "token request service account namespace doesn't match binding")
				assert.Equal(t, binding.Spec.Auth.WorkloadIdentity.ServiceAccountName, serviceAccountName, "token request service account name doesn't match service account configured in binding")
				return &authenticationv1.TokenRequest{
					Status: authenticationv1.TokenRequestStatus{
						Token: "fake-sa-token",
					},
				}, nil
			}, func(ctx context.Context, spec msiacrpullv1beta2.AcrPullBindingSpec, tenantId, clientId, serviceAccountToken string) (azcore.AccessToken, error) {
				assert.Empty(t, cmp.Diff(spec, binding.Spec), "ACR audience Entra token request binding spec mismatch")
				assert.Equal(t, spec.Auth.WorkloadIdentity.TenantID, tenantId, "ACR audience Entra token request tenant id mismatch")
				assert.Equal(t, spec.Auth.WorkloadIdentity.ClientID, clientId, "ACR audience Entra token request client id mismatch")
				assert.Equal(t, "fake-sa-token", serviceAccountToken, "ACR audience Entra token request service account token mismatch")
				return azcore.AccessToken{Token: "fake-arm-token"}, outputError
			}, func(ctx context.Context, acrAudienceEntraToken azcore.AccessToken, spec msiacrpullv1beta2.AcrConfiguration) (azcore.AccessToken, error) {
				assert.Empty(t, cmp.Diff(spec, binding.Spec.ACR), "ACR token exchange binding ACR spec mismatch")
				assert.Equal(t, "fake-arm-token", acrAudienceEntraToken.Token, "ACR token exchange ACR audience Entra token mismatch")
				return output, outputError
			}
	}
}
