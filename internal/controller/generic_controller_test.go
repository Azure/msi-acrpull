package controller

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
)

func TestSortPullSecrets(t *testing.T) {
	for _, testCase := range []struct {
		in  *corev1.ServiceAccount
		out *corev1.ServiceAccount
	}{
		{
			in: &corev1.ServiceAccount{
				ImagePullSecrets: []corev1.LocalObjectReference{
					{Name: "old-msi-acrpull-secret"},
					{Name: "unrelated"},
					{Name: "acr-pull-new"},
					{Name: "zzz-msi-acrpull-secret"},
					{Name: "unrelated-other"},
					{Name: "acr-pull-aa"},
				},
			},
			out: &corev1.ServiceAccount{
				ImagePullSecrets: []corev1.LocalObjectReference{
					{Name: "unrelated"},
					{Name: "unrelated-other"},
					{Name: "acr-pull-aa"},
					{Name: "acr-pull-new"},
					{Name: "old-msi-acrpull-secret"},
					{Name: "zzz-msi-acrpull-secret"},
				},
			},
		},
	} {
		sortPullSecrets(testCase.in)
		if diff := cmp.Diff(testCase.out, testCase.in); diff != "" {
			t.Errorf("%T differ (-got, +want): %s", testCase.in, diff)
		}
	}
}
