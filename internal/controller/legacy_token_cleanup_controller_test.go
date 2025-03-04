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
		name         string
		acrBinding   *msiacrpullv1beta1.AcrPullBinding
		legacySecret *corev1.Secret

		action *cleanupAction
	}{
		{
			name: "legacy secret exists, label the secret",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "binding"},
			},
			legacySecret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "binding-msi-acrpull-secret"}},
			action: &cleanupAction{
				updateSecret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "binding-msi-acrpull-secret",
						Labels: map[string]string{
							"acr.microsoft.com/binding": "binding",
						},
					},
				},
			},
		},
		{
			name: "legacy secret exists, already labelled, check for done",
			acrBinding: &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "binding"},
			},
			legacySecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "binding-msi-acrpull-secret",
					Labels: map[string]string{
						"acr.microsoft.com/binding": "binding",
					},
				},
			},
			action: &cleanupAction{
				checkCompletion: true,
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			controller := LegacyTokenCleanupController{
				Client: nil,
				Log:    ctrl.Log.WithName("test"),
			}
			got := controller.reconcile(testCase.acrBinding, testCase.legacySecret)
			if diff := cmp.Diff(testCase.action, got, cmp.AllowUnexported(cleanupAction{})); diff != "" {
				t.Errorf("-want, +got:\n%s", diff)
			}
		})
	}
}
