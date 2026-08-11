package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
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

func TestPullSecretForUpdatePreservesMetadataAndExecutes(t *testing.T) {
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "ns",
			Name:            "pull-secret",
			ResourceVersion: "7",
			UID:             types.UID("existing-uid"),
			Labels: map[string]string{
				"custom-label":      "preserved",
				ACRPullBindingLabel: "old-binding",
			},
			Annotations: map[string]string{
				"custom-annotation":   "preserved",
				tokenExpiryAnnotation: "old-expiry",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"old": []byte("data")},
	}
	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns",
			Name:      "pull-secret",
			Labels:    map[string]string{ACRPullBindingLabel: "binding"},
			Annotations: map[string]string{
				tokenExpiryAnnotation:  "new-expiry",
				tokenRefreshAnnotation: "new-refresh",
				tokenInputsAnnotation:  "new-inputs",
			},
		},
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{dockerConfigKey: []byte("new-data")},
	}

	updated := pullSecretForUpdate(existing, desired)
	if updated.ResourceVersion != existing.ResourceVersion || updated.UID != existing.UID {
		t.Fatalf("server metadata was not preserved: %#v", updated.ObjectMeta)
	}
	if updated.Labels["custom-label"] != "preserved" || updated.Annotations["custom-annotation"] != "preserved" {
		t.Fatalf("custom metadata was not preserved: labels=%v annotations=%v", updated.Labels, updated.Annotations)
	}

	client := &recordingClient{}
	result, err := (&action[*msiacrpullv1beta1.AcrPullBinding]{updateSecret: updated}).execute(
		context.Background(),
		logr.Discard(),
		client,
		func(*msiacrpullv1beta1.AcrPullBinding) time.Duration { return 0 },
	)
	if err != nil {
		t.Fatalf("failed to update existing Secret: %v", err)
	}
	if !result.IsZero() {
		t.Fatalf("expected empty result, got %#v", result)
	}

	stored, ok := client.updated.(*corev1.Secret)
	if !ok {
		t.Fatalf("expected updated Secret, got %T", client.updated)
	}
	if diff := cmp.Diff(desired.Data, stored.Data); diff != "" {
		t.Errorf("Secret data differs (-want, +got): %s", diff)
	}
	if stored.Labels["custom-label"] != "preserved" || stored.Annotations["custom-annotation"] != "preserved" {
		t.Errorf("stored custom metadata was not preserved: labels=%v annotations=%v", stored.Labels, stored.Annotations)
	}
}

func TestActionExecutePersistsStatusAndReturnsTransientError(t *testing.T) {
	binding := &msiacrpullv1beta1.AcrPullBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "binding"},
	}
	client := &recordingClient{statusWriter: &recordingStatusWriter{}}

	updated := binding.DeepCopy()
	updated.Status.Error = "temporary Azure outage"
	result, err := (&action[*msiacrpullv1beta1.AcrPullBinding]{
		updatePullBindingStatus: updated,
		retryError:              updated.Status.Error,
	}).execute(
		context.Background(),
		logr.Discard(),
		client,
		func(*msiacrpullv1beta1.AcrPullBinding) time.Duration { return 0 },
	)
	if err == nil || !strings.Contains(err.Error(), updated.Status.Error) {
		t.Fatalf("expected transient reconcile error, got %v", err)
	}
	if !result.IsZero() {
		t.Fatalf("expected controller-runtime to determine backoff, got %#v", result)
	}

	stored, ok := client.statusWriter.updated.(*msiacrpullv1beta1.AcrPullBinding)
	if !ok {
		t.Fatalf("expected updated binding status, got %T", client.statusWriter.updated)
	}
	if stored.Status.Error != updated.Status.Error {
		t.Fatalf("expected persisted status error %q, got %q", updated.Status.Error, stored.Status.Error)
	}
}

type recordingClient struct {
	crclient.Client
	updated      crclient.Object
	statusWriter *recordingStatusWriter
}

func (c *recordingClient) Update(_ context.Context, obj crclient.Object, _ ...crclient.UpdateOption) error {
	c.updated = obj.DeepCopyObject().(crclient.Object)
	return nil
}

func (c *recordingClient) Status() crclient.SubResourceWriter {
	return c.statusWriter
}

type recordingStatusWriter struct {
	crclient.SubResourceWriter
	updated crclient.Object
}

func (w *recordingStatusWriter) Update(_ context.Context, obj crclient.Object, _ ...crclient.SubResourceUpdateOption) error {
	w.updated = obj.DeepCopyObject().(crclient.Object)
	return nil
}
