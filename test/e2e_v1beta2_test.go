//go:build e2e

package test

import (
	"context"
	"testing"

	msiacrpullv1beta2 "github.com/Azure/msi-acrpull/api/v1beta2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func TestManagedIdentityPulls_v1beta2(t *testing.T) {
	testACRPullBinding[*msiacrpullv1beta2.AcrPullBinding](t, "v1beta2-msi-", func(namespace, name, scope, serviceAccount string, cfg *Config) *msiacrpullv1beta2.AcrPullBinding {
		return &msiacrpullv1beta2.AcrPullBinding{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Spec: msiacrpullv1beta2.AcrPullBindingSpec{
				ACR: msiacrpullv1beta2.AcrConfiguration{
					Server:      cfg.RegistryFQDN,
					Scope:       scope,
					Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
				},
				Auth: msiacrpullv1beta2.AuthenticationMethod{
					ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{
						ClientID:   "",
						ResourceID: cfg.PullerResourceID,
					},
				},
				ServiceAccountName: serviceAccount,
			},
		}
	}, func(client crclient.Client, namespace, name string) func(ctx context.Context) (*msiacrpullv1beta2.AcrPullBinding, error) {
		return func(ctx context.Context) (*msiacrpullv1beta2.AcrPullBinding, error) {
			thisBinding := msiacrpullv1beta2.AcrPullBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
			err := client.Get(ctx, crclient.ObjectKeyFromObject(&thisBinding), &thisBinding)
			return &thisBinding, err
		}
	}, false)
}

func TestWorkloadIdentityPulls_v1beta2(t *testing.T) {
	testACRPullBinding[*msiacrpullv1beta2.AcrPullBinding](t, "v1beta2-wi-", func(namespace, name, scope, serviceAccount string, cfg *Config) *msiacrpullv1beta2.AcrPullBinding {
		return &msiacrpullv1beta2.AcrPullBinding{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Spec: msiacrpullv1beta2.AcrPullBindingSpec{
				ACR: msiacrpullv1beta2.AcrConfiguration{
					Server:      cfg.RegistryFQDN,
					Scope:       scope,
					Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
				},
				Auth: msiacrpullv1beta2.AuthenticationMethod{
					WorkloadIdentity: &msiacrpullv1beta2.WorkloadIdentityAuth{
						ServiceAccountName: serviceAccount,
					},
				},
				ServiceAccountName: serviceAccount,
			},
		}
	}, func(client crclient.Client, namespace, name string) func(ctx context.Context) (*msiacrpullv1beta2.AcrPullBinding, error) {
		return func(ctx context.Context) (*msiacrpullv1beta2.AcrPullBinding, error) {
			thisBinding := msiacrpullv1beta2.AcrPullBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
			err := client.Get(ctx, crclient.ObjectKeyFromObject(&thisBinding), &thisBinding)
			return &thisBinding, err
		}
	}, true)
}
