package controller

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/google/go-cmp/cmp"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
)

func Test_LegacyTokenCleanupController_reconcile(t *testing.T) {
	for _, testCase := range []struct {
		name           string
		acrBinding     *msiacrpullv1beta1.AcrPullBinding
		serviceAccount *corev1.ServiceAccount
		legacySecret   *corev1.Secret

		action *cleanupAction
	}{
		{
			name:       "legacy secret exists, but no new secret generated, do nothing",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{ObjectMeta: metav1.ObjectMeta{Name: "binding"}},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Name: "default"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "binding-msi-acrpull-secret"}},
			},
			legacySecret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "binding-msi-acrpull-secret"}},
		},
		{
			name:       "legacy secret exists, new secret generated, clean up service account",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{ObjectMeta: metav1.ObjectMeta{Name: "binding"}},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Name: "default"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "binding-msi-acrpull-secret"}, {Name: "acr-pull-binding-37d7ayn69u"}},
			},
			legacySecret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "binding-msi-acrpull-secret"}},
			action: &cleanupAction{
				updateServiceAccount: &corev1.ServiceAccount{
					ObjectMeta:       metav1.ObjectMeta{Name: "default"},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding-37d7ayn69u"}},
				},
			},
		},
		{
			name:       "legacy secret exists, new secret generated, service account cleaned up, delete secret",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{ObjectMeta: metav1.ObjectMeta{Name: "binding"}},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Name: "default"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding-37d7ayn69u"}},
			},
			legacySecret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "binding-msi-acrpull-secret"}},
			action: &cleanupAction{
				deleteSecret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "binding-msi-acrpull-secret"}},
			},
		},
		{
			name:       "legacy secret gone, new secret generated, clean up service account",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{ObjectMeta: metav1.ObjectMeta{Name: "binding"}},
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta:       metav1.ObjectMeta{Name: "default"},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "binding-msi-acrpull-secret"}, {Name: "acr-pull-binding-37d7ayn69u"}},
			},
			action: &cleanupAction{
				updateServiceAccount: &corev1.ServiceAccount{
					ObjectMeta:       metav1.ObjectMeta{Name: "default"},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "acr-pull-binding-37d7ayn69u"}},
				},
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			controller := LegacyTokenCleanupController{
				Client: nil,
				Log:    ctrl.Log.WithName("test"),
			}
			got := controller.reconcile(testCase.acrBinding, testCase.serviceAccount, testCase.legacySecret)
			if diff := cmp.Diff(testCase.action, got, cmp.AllowUnexported(cleanupAction{})); diff != "" {
				t.Errorf("-want, +got:\n%s", diff)
			}
		})
	}
}
