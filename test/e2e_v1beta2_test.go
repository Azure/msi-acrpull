//go:build e2e

package test

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	msiacrpullv1beta2 "github.com/Azure/msi-acrpull/api/v1beta2"
	"github.com/Azure/msi-acrpull/internal/controller"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	clientgorest "k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
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
	}, true, func(prefix string, cfg *Config, ctx context.Context, client crclient.Client, nodeSelector map[string]string, t *testing.T) {
		t.Run("pulls succeed with acrpullbinding referencing non-default service account", func(t *testing.T) {
			t.Parallel()

			namespace := prefix + "nondefault"
			t.Logf("creating namespace %s", namespace)
			if err := client.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil && !errors.IsAlreadyExists(err) {
				t.Fatalf("failed to create namespace %s: %v", namespace, err)
			}

			t.Cleanup(func() {
				if _, skip := os.LookupEnv("SKIP_CLEANUP"); skip {
					return
				}
				if err := client.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
					t.Logf("failed to delete namespace %s: %v", namespace, err)
				}
			})

			const serviceAccount = "sa"
			t.Logf("creating service account %s/%s", namespace, serviceAccount)
			sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: serviceAccount}}
			if err := client.Create(ctx, sa); err != nil && !errors.IsAlreadyExists(err) {
				t.Fatalf("failed to create service account %s/%s: %v", namespace, serviceAccount, err)
			}

			const pullBinding = "pull-binding"
			t.Logf("creating pull binding %s/%s", namespace, pullBinding)
			if err := client.Create(ctx, &msiacrpullv1beta2.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: pullBinding},
				Spec: msiacrpullv1beta2.AcrPullBindingSpec{
					ACR: msiacrpullv1beta2.AcrConfiguration{
						Server:      cfg.RegistryFQDN,
						Scope:       "repository:alice:pull",
						Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
					},
					Auth: msiacrpullv1beta2.AuthenticationMethod{
						WorkloadIdentity: &msiacrpullv1beta2.WorkloadIdentityAuth{
							ServiceAccountName: serviceAccount,
							ClientID:           cfg.PullerClientID,
							TenantID:           cfg.PullerTenantID,
						},
					},
					ServiceAccountName: serviceAccount,
				},
			}); err != nil {
				t.Fatalf("failed to create pull binding %s/%s: %v", namespace, pullBinding, err)
			}
			eventuallyFulfillPullBinding[*msiacrpullv1beta2.AcrPullBinding](t, ctx, client, namespace, pullBinding, func(namespace, name string) *msiacrpullv1beta2.AcrPullBinding {
				return &msiacrpullv1beta2.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
				}
			})
			validateScopedPods(ctx, t, cfg, namespace, serviceAccount, client, nodeSelector)
		})
	})
}

func TestScopeRequired(t *testing.T) {
	t.Parallel()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}

	client, err := ClientFor(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if deadline, ok := t.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		t.Cleanup(cancel)
	}

	const namespace = "default"
	const name = "fail"
	if err := client.Create(ctx, &msiacrpullv1beta2.AcrPullBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: msiacrpullv1beta2.AcrPullBindingSpec{
			ACR: msiacrpullv1beta2.AcrConfiguration{
				Server:      cfg.RegistryFQDN,
				Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
			},
			Auth: msiacrpullv1beta2.AuthenticationMethod{
				WorkloadIdentity: &msiacrpullv1beta2.WorkloadIdentityAuth{
					ServiceAccountName: "whatever",
				},
			},
			ServiceAccountName: "whatever",
		},
	}); err == nil || !strings.Contains(err.Error(), "spec.acr.scope in body should be at least 1 chars long") {
		t.Errorf("expected to fail creating ACRPullBinding without registry scope, but didn't (err=%v)", err)
	}

	t.Cleanup(func() {
		if _, skip := os.LookupEnv("SKIP_CLEANUP"); skip {
			return
		}
		if err := client.Delete(ctx, &msiacrpullv1beta2.AcrPullBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}); err != nil && !errors.IsNotFound(err) {
			t.Logf("failed to delete pull binding %s/%s: %v", namespace, name, err)
		}
	})
}

func TestValidatingAdmissionPolicies(t *testing.T) {
	t.Parallel()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}

	client, err := ClientFor(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if deadline, ok := t.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		t.Cleanup(cancel)
	}

	var configMaps corev1.ConfigMapList
	if err := client.List(ctx, &configMaps, crclient.MatchingLabels{
		"app.kubernetes.io/name": "acrpull",
	}); err != nil {
		t.Fatalf("failed to list validating admission policy configurations: %v", err)
	}
	if len(configMaps.Items) != 1 {
		t.Fatalf("did not find one validating admission policy configuration, but %d", len(configMaps.Items))
	}
	configuration := configMaps.Items[0]
	var serviceAccountNamespace, serviceAccountName, tokenAudience string
	for from, into := range map[string]*string{
		"controllerNamespace":          &serviceAccountNamespace,
		"controllerServiceAccountName": &serviceAccountName,
		"tokenAudience":                &tokenAudience,
	} {
		value, set := configuration.Data[from]
		if !set {
			t.Fatalf("validating admission policy configuration %s/%s doesn't have parameter field %s set", configuration.Namespace, configuration.Name, from)
		}
		*into = value
	}

	restConfig, err := RestConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create rest config: %v", err)
	}
	kubeClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		t.Fatalf("failed to create kube client: %v", err)
	}

	resp, err := kubeClient.CoreV1().ServiceAccounts(serviceAccountNamespace).CreateToken(ctx, serviceAccountName, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create token for service account %s/%s: %v", serviceAccountNamespace, serviceAccountName, err)
	}
	if resp.Status.Token == "" {
		t.Fatalf("token response for service account %s/%s did not have a token", serviceAccountNamespace, serviceAccountName)
	}

	saConfig := clientgorest.AnonymousClientConfig(restConfig)
	saConfig.BearerToken = resp.Status.Token

	saClient, err := kubernetes.NewForConfig(saConfig)
	if err != nil {
		t.Fatalf("failed to create kube client for service account %s/%s: %v", serviceAccountNamespace, serviceAccountName, err)
	}

	response, err := saClient.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("could not send SSR: %v", err)
	}
	if got, want := response.Status.UserInfo.Username, fmt.Sprintf("system:serviceaccount:%s:%s", serviceAccountNamespace, serviceAccountName); got != want {
		t.Fatalf("got incorrect username in SSR: wanted %q, got %q", want, got)
	}

	t.Run("token requests", func(t *testing.T) {
		t.Parallel()
		t.Run("succeeds in requesting token for correct audience", func(t *testing.T) {
			t.Parallel()
			resp, err := saClient.CoreV1().ServiceAccounts("default").CreateToken(ctx, "default", &authenticationv1.TokenRequest{
				Spec: authenticationv1.TokenRequestSpec{
					Audiences: []string{tokenAudience},
				},
			}, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("failed to send token request with correct audience: %v", err)
			}
			if resp.Status.Token == "" {
				t.Fatalf("token request returned an empty token response")
			}
		})

		t.Run("fails in requesting token for incorrect audience", func(t *testing.T) {
			t.Parallel()
			resp, err := saClient.CoreV1().ServiceAccounts("default").CreateToken(ctx, "default", &authenticationv1.TokenRequest{
				Spec: authenticationv1.TokenRequestSpec{
					Audiences: []string{"https://kubernetes.default.svc"},
				},
			}, metav1.CreateOptions{})
			if err == nil {
				t.Fatalf("incorrectly succeeded to send token request with k8s API audience")
			}
			if resp.Status.Token != "" {
				t.Fatalf("token request returned a token for invalid audience")
			}
		})
	})

	t.Run("secrets", func(t *testing.T) {
		t.Parallel()

		namespace := "vap-secrets-test"
		t.Logf("creating namespace %s", namespace)
		if err := client.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil && !errors.IsAlreadyExists(err) {
			t.Fatalf("failed to create namespace %s: %v", namespace, err)
		}

		t.Cleanup(func() {
			if _, skip := os.LookupEnv("SKIP_CLEANUP"); skip {
				return
			}
			if err := client.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
				t.Logf("failed to delete namespace %s: %v", namespace, err)
			}
		})

		t.Run("can't create service account token secrets", func(t *testing.T) {
			t.Parallel()

			if _, err := saClient.CoreV1().Secrets(namespace).Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "token",
					Namespace: namespace,
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: "acrpull.microsoft.com/v1beta2",
						Kind:       "AcrPullBinding",
						Name:       "binding",
						Controller: ptr.To(true),
						UID:        "1234",
					}},
					Labels: map[string]string{
						controller.ACRPullBindingLabel: "binding",
					},
					Annotations: map[string]string{
						corev1.ServiceAccountNameKey: "test",
					},
				},
				Type: corev1.SecretTypeServiceAccountToken,
			}, metav1.CreateOptions{}); err == nil || !strings.Contains(err.Error(), "The controller can only create or update secrets that it owns, with the correct type and having the correct label.") {
				t.Fatalf("created service account token secret: %v", err)
			}
		})

		t.Run("can't adopt existing secrets", func(t *testing.T) {
			t.Parallel()

			const name = "existing"
			existing, createErr := kubeClient.CoreV1().Secrets(namespace).Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Type: corev1.SecretTypeOpaque,
			}, metav1.CreateOptions{})
			if createErr != nil {
				t.Fatalf("failed to seed existing secret: %v", createErr)
			}
			if existing == nil {
				t.Fatalf("secret %s is nil", name)
			}

			updated := existing.DeepCopy()
			updated.Labels = map[string]string{
				controller.ACRPullBindingLabel: "binding",
			}
			updated.OwnerReferences = []metav1.OwnerReference{{
				APIVersion: "acrpull.microsoft.com/v1beta2",
				Kind:       "AcrPullBinding",
				Name:       "binding",
				Controller: ptr.To(true),
				UID:        "1234",
			}}
			if _, err := saClient.CoreV1().Secrets(namespace).Update(ctx, updated, metav1.UpdateOptions{}); err == nil || !strings.Contains(err.Error(), "The controller can only create or update secrets that it owns, with the correct type and having the correct label.") {
				t.Fatalf("adopted existing secret: %v", err)
			}
		})
	})

	t.Run("serviceaccounts", func(t *testing.T) {
		t.Parallel()

		namespace := "vap-serviceaccounts-test"
		t.Logf("creating namespace %s", namespace)
		if err := client.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil && !errors.IsAlreadyExists(err) {
			t.Fatalf("failed to create namespace %s: %v", namespace, err)
		}

		t.Cleanup(func() {
			if _, skip := os.LookupEnv("SKIP_CLEANUP"); skip {
				return
			}
			if err := client.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
				t.Logf("failed to delete namespace %s: %v", namespace, err)
			}
		})

		saName := "sa"
		serviceAccount, createErr := kubeClient.CoreV1().ServiceAccounts(namespace).Create(ctx, &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: saName},
			Secrets:    []corev1.ObjectReference{{Name: "something"}},
			ImagePullSecrets: []corev1.LocalObjectReference{
				{Name: "unrelated"}, {Name: "acr-pull-binding-kfhdsuengf"},
			},
			AutomountServiceAccountToken: ptr.To(true),
		}, metav1.CreateOptions{})
		if createErr != nil {
			t.Fatalf("failed to create service account %s/%s: %v", namespace, saName, createErr)
		}

		t.Run("can't change service account options", func(t *testing.T) {
			t.Parallel()
			updated := serviceAccount.DeepCopy()
			updated.ResourceVersion = ""
			updated.AutomountServiceAccountToken = ptr.To(false)
			if _, err := saClient.CoreV1().ServiceAccounts(namespace).Update(ctx, updated, metav1.UpdateOptions{}); err == nil || !strings.Contains(err.Error(), "The controller may only update service accounts to add or remove pull secrets that the controller manages") {
				t.Fatalf("changed service account options: %v", err)
			}
		})

		t.Run("can't change service account token secrets", func(t *testing.T) {
			t.Parallel()
			updated := serviceAccount.DeepCopy()
			updated.ResourceVersion = ""
			updated.Secrets = append(updated.Secrets, corev1.ObjectReference{Name: "injected"})
			if _, err := saClient.CoreV1().ServiceAccounts(namespace).Update(ctx, updated, metav1.UpdateOptions{}); err == nil || !strings.Contains(err.Error(), "The controller may only update service accounts to add or remove pull secrets that the controller manages") {
				t.Fatalf("changed service account tokens: %v", err)
			}
		})

		t.Run("image pull secrets", func(t *testing.T) {
			t.Parallel()
			t.Run("can't add non-managed secrets", func(t *testing.T) {
				updated := serviceAccount.DeepCopy()
				updated.ResourceVersion = ""
				updated.ImagePullSecrets = append(updated.ImagePullSecrets, corev1.LocalObjectReference{Name: "injected"})
				if _, err := saClient.CoreV1().ServiceAccounts(namespace).Update(ctx, updated, metav1.UpdateOptions{}); err == nil || !strings.Contains(err.Error(), "The controller may only update service accounts to add or remove pull secrets that the controller manages.") {
					t.Fatalf("added unmanaged image pull secret: %v", err)
				}
			})
			t.Run("can't remove non-managed secrets", func(t *testing.T) {
				updated := serviceAccount.DeepCopy()
				updated.ResourceVersion = ""
				updated.ImagePullSecrets = nil
				if _, err := saClient.CoreV1().ServiceAccounts(namespace).Update(ctx, updated, metav1.UpdateOptions{}); err == nil || !strings.Contains(err.Error(), "The controller may only update service accounts to add or remove pull secrets that the controller manages.") {
					t.Fatalf("removed unmanaged image pull secret: %v", err)
				}
			})
			t.Run("can add managed secrets", func(t *testing.T) {
				updated := serviceAccount.DeepCopy()
				updated.ResourceVersion = ""
				updated.ImagePullSecrets = append(updated.ImagePullSecrets, corev1.LocalObjectReference{Name: "acr-pull-binding-kjfhdhfjuj"})
				if _, err := saClient.CoreV1().ServiceAccounts(namespace).Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
					t.Fatalf("couldn't add new managed image pull secret: %v", err)
				}
			})
			t.Run("can remove managed secrets", func(t *testing.T) {
				updated := serviceAccount.DeepCopy()
				updated.ResourceVersion = ""
				updated.ImagePullSecrets = slices.DeleteFunc(updated.ImagePullSecrets, func(reference corev1.LocalObjectReference) bool {
					return strings.HasPrefix(reference.Name, "acr-pull-binding-")
				})
				if _, err := saClient.CoreV1().ServiceAccounts(namespace).Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
					t.Fatalf("couldn't remove managed image pull secrets: %v", err)
				}
			})

			t.Run("can add to new service account", func(t *testing.T) {
				t.Parallel()

				saName := "existing-sa"
				serviceAccount, createErr := kubeClient.CoreV1().ServiceAccounts(namespace).Create(ctx, &corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: saName},
				}, metav1.CreateOptions{})
				if createErr != nil {
					t.Fatalf("failed to create service account %s/%s: %v", namespace, saName, createErr)
				}

				updated := serviceAccount.DeepCopy()
				updated.ResourceVersion = ""
				updated.ImagePullSecrets = append(updated.ImagePullSecrets, corev1.LocalObjectReference{Name: "acr-pull-binding-kjfhdhfjuj"})
				if _, err := saClient.CoreV1().ServiceAccounts(namespace).Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
					t.Fatalf("couldn't add new managed image pull secret: %v", err)
				}
			})
		})
	})
}
