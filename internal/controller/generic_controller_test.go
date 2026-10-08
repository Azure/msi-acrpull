package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
	msiacrpullv1beta2 "github.com/Azure/msi-acrpull/api/v1beta2"
	"github.com/Azure/msi-acrpull/pkg/authorizer/mock_authorizer"
	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
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

func TestActionExecuteReturnsTransientErrorWithoutStatusUpdate(t *testing.T) {
	client := &recordingClient{statusWriter: &recordingStatusWriter{}}
	result, err := (&action[*msiacrpullv1beta1.AcrPullBinding]{
		retryError: "temporary Azure outage",
	}).execute(
		context.Background(),
		logr.Discard(),
		client,
		func(*msiacrpullv1beta1.AcrPullBinding) time.Duration { return 0 },
	)
	if err == nil || !strings.Contains(err.Error(), "temporary Azure outage") {
		t.Fatalf("expected transient reconcile error, got %v", err)
	}
	if !result.IsZero() {
		t.Fatalf("expected controller-runtime to determine backoff, got %#v", result)
	}
	if client.statusWriter.updated != nil {
		t.Fatalf("expected no status update, got %T", client.statusWriter.updated)
	}
}

func TestCredentialStatusMessageUsesStructuredResponseError(t *testing.T) {
	statuses := make([]string, 0, 2)
	for _, correlationID := range []string{
		"92b4e2ff-be91-4ad1-bc95-ea0337098e30",
		"336c85eb-f609-45c2-8a53-89396db5c5a3",
	} {
		body := fmt.Sprintf(`{"errors":[{"code":"REQUEST_BODY_INVALID","message":"Request body is invalid. CorrelationId: %s"}]}`, correlationID)
		err := credentialGenerationError{
			operation: "failed to retrieve ACR token",
			err: &azcore.ResponseError{
				StatusCode: http.StatusBadRequest,
				RawResponse: &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
				},
			},
		}
		statuses = append(statuses, credentialStatusMessage(err))
	}

	const expected = "failed to retrieve ACR token: request failed with HTTP status 400: REQUEST_BODY_INVALID"
	for _, status := range statuses {
		if status != expected {
			t.Fatalf("expected stable structured status %q, got %q", expected, status)
		}
	}

	binding := &msiacrpullv1beta1.AcrPullBinding{
		Status: msiacrpullv1beta1.AcrPullBindingStatus{Error: statuses[0]},
	}
	reconciler := &genericReconciler[*msiacrpullv1beta1.AcrPullBinding]{
		GetStatusError: func(binding *msiacrpullv1beta1.AcrPullBinding) string {
			return binding.Status.Error
		},
		UpdateStatusError: func(*msiacrpullv1beta1.AcrPullBinding, string) *msiacrpullv1beta1.AcrPullBinding {
			t.Fatal("stable authentication error should not update status")
			return nil
		},
	}
	action := reconciler.statusErrorAction(binding, statuses[1], true)
	if action.updatePullBindingStatus != nil || action.retryError != statuses[1] {
		t.Fatalf("expected retry without status update, got %#v", action)
	}
}

func TestCredentialStatusMessageUsesStructuredAuthenticationError(t *testing.T) {
	const body = `{"errors":[{"code":"IDENTITY_NOT_FOUND","message":"The requested identity wasn't found"}]}`
	err := credentialGenerationError{
		operation: "failed to retrieve ARM token",
		err: &azidentity.AuthenticationFailedError{
			RawResponse: &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(strings.NewReader(body)),
			},
		},
	}

	const expected = "failed to retrieve ARM token: request failed with HTTP status 400: IDENTITY_NOT_FOUND"
	if status := credentialStatusMessage(err); status != expected {
		t.Fatalf("expected structured status %q, got %q", expected, status)
	}
}

func TestCredentialStatusMessageNormalizesAuthenticationPayloads(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		body  string
		codes string
	}{
		{
			name:  "managed identity",
			body:  `{"error":"invalid_request","error_description":"Identity not found. Correlation ID: %[1]s. Timestamp: %[2]s","correlation_id":"%[1]s"}`,
			codes: "invalid_request",
		},
		{
			name:  "Entra",
			body:  `{"error":"invalid_client","error_description":"AADSTS700016: Application was not found in the directory.\r\nTrace ID: %[1]s\r\nCorrelation ID: %[1]s\r\nTimestamp: %[2]s","error_codes":[700016],"timestamp":"%[2]s","trace_id":"%[1]s","correlation_id":"%[1]s","error_uri":"https://login.microsoftonline.com/error?code=700016"}`,
			codes: "700016, invalid_client",
		},
		{
			name:  "different Entra code",
			body:  `{"error":"invalid_client","error_codes":[7000215],"error_description":"Invalid client secret. Correlation ID: %[1]s. Timestamp: %[2]s"}`,
			codes: "7000215, invalid_client",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			expected := "failed to retrieve ARM token: request failed with HTTP status 400: " + testCase.codes
			for attempt, requestID := range []string{
				"92b4e2ff-be91-4ad1-bc95-ea0337098e30",
				"336c85eb-f609-45c2-8a53-89396db5c5a3",
			} {
				body := fmt.Sprintf(testCase.body, requestID, fmt.Sprintf("2026-10-08 15:31:%02dZ", attempt))
				err := credentialGenerationError{
					operation: "failed to retrieve ARM token",
					err: &azidentity.AuthenticationFailedError{
						RawResponse: &http.Response{
							StatusCode: http.StatusBadRequest,
							Body:       io.NopCloser(strings.NewReader(body)),
						},
					},
				}
				if status := credentialStatusMessage(err); status != expected {
					t.Fatalf("expected stable authentication status %q, got %q", expected, status)
				}
			}
		})
	}
}

func TestCredentialStatusMessageSortsAndDeduplicatesCodes(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		bodies []string
		codes  string
	}{
		{
			name: "ACR",
			bodies: []string{
				`{"errors":[{"code":"UNAUTHORIZED"},{"code":"DENIED"},{"code":"UNAUTHORIZED"},{"code":""}]}`,
				`{"errors":[{"code":"DENIED"},{"code":"UNAUTHORIZED"}]}`,
			},
			codes: "DENIED, UNAUTHORIZED",
		},
		{
			name: "Entra",
			bodies: []string{
				`{"error":"invalid_client","error_codes":[7000215,700016,7000215]}`,
				`{"error":"invalid_client","error_codes":[700016,7000215]}`,
			},
			codes: "700016, 7000215, invalid_client",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			expected := "failed to generate pull credential: request failed with HTTP status 400: " + testCase.codes
			for _, body := range testCase.bodies {
				err := &azcore.ResponseError{
					RawResponse: &http.Response{
						StatusCode: http.StatusBadRequest,
						Body:       io.NopCloser(strings.NewReader(body)),
					},
				}
				if status := credentialStatusMessage(err); status != expected {
					t.Fatalf("expected sorted, unique codes %q, got %q", expected, status)
				}
			}
		})
	}
}

func TestReconcilersRetryCredentialErrorsWithoutStatusChurn(t *testing.T) {
	for _, errorCase := range []struct {
		name  string
		codes string
		err   func(string) error
	}{
		{
			name:  "ACR response",
			codes: "REQUEST_BODY_INVALID",
			err: func(correlationID string) error {
				return &azcore.ResponseError{
					StatusCode: http.StatusBadRequest,
					RawResponse: &http.Response{
						StatusCode: http.StatusBadRequest,
						Body: io.NopCloser(strings.NewReader(fmt.Sprintf(
							`{"errors":[{"code":"REQUEST_BODY_INVALID","message":"Request body is invalid. CorrelationId: %s"}]}`, correlationID))),
					},
				}
			},
		},
		{
			name:  "Entra authentication",
			codes: "700016, invalid_client",
			err: func(correlationID string) error {
				return &azidentity.AuthenticationFailedError{
					RawResponse: &http.Response{
						StatusCode: http.StatusBadRequest,
						Body: io.NopCloser(strings.NewReader(fmt.Sprintf(
							`{"error":"invalid_client","error_description":"AADSTS700016: Application was not found.\r\nTrace ID: %[1]s\r\nCorrelation ID: %[1]s","error_codes":[700016],"trace_id":"%[1]s","correlation_id":"%[1]s"}`, correlationID))),
					},
				}
			},
		},
		{
			name:  "managed identity authentication",
			codes: "invalid_request",
			err: func(correlationID string) error {
				return &azidentity.AuthenticationFailedError{
					RawResponse: &http.Response{
						StatusCode: http.StatusBadRequest,
						Body: io.NopCloser(strings.NewReader(fmt.Sprintf(
							`{"error":"invalid_request","error_description":"Identity not found. Correlation ID: %s"}`, correlationID))),
					},
				}
			},
		},
	} {
		for _, path := range []string{"v1beta1 ACR access token", "v1beta2 ARM token", "v1beta2 ACR token"} {
			t.Run(path+"/"+errorCase.name, func(t *testing.T) {
				ctx := context.Background()
				s := runtime.NewScheme()
				if err := corev1.AddToScheme(s); err != nil {
					t.Fatal(err)
				}
				if err := msiacrpullv1beta1.AddToScheme(s); err != nil {
					t.Fatal(err)
				}
				if err := msiacrpullv1beta2.AddToScheme(s); err != nil {
					t.Fatal(err)
				}
				meta := metav1.ObjectMeta{
					Namespace: "ns", Name: "binding", Finalizers: []string{msiAcrPullFinalizerName},
				}
				var binding crclient.Object
				if path == "v1beta1 ACR access token" {
					binding = &msiacrpullv1beta1.AcrPullBinding{
						ObjectMeta: meta,
						Spec: msiacrpullv1beta1.AcrPullBindingSpec{
							AcrServer: "registry.azurecr.io", ServiceAccountName: "delegate",
						},
					}
				} else {
					binding = &msiacrpullv1beta2.AcrPullBinding{
						ObjectMeta: meta,
						Spec: msiacrpullv1beta2.AcrPullBindingSpec{
							ServiceAccountName: "delegate",
							ACR:                msiacrpullv1beta2.AcrConfiguration{Server: "registry.azurecr.io"},
							Auth: msiacrpullv1beta2.AuthenticationMethod{
								ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{ClientID: "identity"},
							},
						},
					}
				}
				sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "delegate"}}
				fakeClient := fake.NewClientBuilder().WithScheme(s).
					WithObjects(binding, sa).WithStatusSubresource(binding).
					WithIndex(&corev1.Secret{}, pullBindingField, indexPullSecretByPullBinding).
					WithIndex(&corev1.ServiceAccount{}, imagePullSecretsField, func(crclient.Object) []string { return nil }).
					Build()
				client := &recordingClient{
					Client:       fakeClient,
					statusWriter: &recordingStatusWriter{SubResourceWriter: fakeClient.Status()},
				}
				var sdkErr error
				calls := 0
				var reconciler reconcile.Reconciler
				var operation string
				if path == "v1beta1 ACR access token" {
					auth := mock_authorizer.NewMockInterface(gomock.NewController(t))
					auth.EXPECT().AcquireACRAccessToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
						DoAndReturn(func(context.Context, string, string, string, string) (azcore.AccessToken, error) {
							calls++
							return azcore.AccessToken{}, sdkErr
						}).Times(2)
					reconciler = NewV1beta1Reconciler(&V1beta1ReconcilerOpts{
						CoreOpts: CoreOpts{Client: client, Scheme: s, Logger: logr.Discard()}, Auth: auth,
					})
					operation = "failed to retrieve ACR access token"
				} else {
					reconciler = NewV1beta2Reconciler(&V1beta2ReconcilerOpts{
						CoreOpts: CoreOpts{Client: client, Scheme: s, Logger: logr.Discard()},
						fetchArmToken: func(context.Context, msiacrpullv1beta2.AcrPullBindingSpec, string, string, string) (azcore.AccessToken, error) {
							if path == "v1beta2 ARM token" {
								calls++
								return azcore.AccessToken{}, sdkErr
							}
							return azcore.AccessToken{Token: "arm-token"}, nil
						},
						exchangeArmTokenForAcrToken: func(context.Context, azcore.AccessToken, msiacrpullv1beta2.AcrConfiguration) (azcore.AccessToken, error) {
							if path == "v1beta2 ARM token" {
								t.Fatal("ACR exchange should not run after ARM token failure")
							}
							calls++
							return azcore.AccessToken{}, sdkErr
						},
					})
					operation = "failed to retrieve ARM token"
					if path == "v1beta2 ACR token" {
						operation = "failed to retrieve ACR token"
					}
				}
				expected := operation + ": request failed with HTTP status 400: " + errorCase.codes
				expectedRetry := "retrying after credential generation failure: " + expected
				req := ctrl.Request{NamespacedName: crclient.ObjectKeyFromObject(binding)}
				for attempt, correlationID := range []string{
					"92b4e2ff-be91-4ad1-bc95-ea0337098e30",
					"336c85eb-f609-45c2-8a53-89396db5c5a3",
				} {
					sdkErr = errorCase.err(correlationID)
					result, err := reconciler.Reconcile(ctx, req)
					if err == nil || err.Error() != expectedRetry {
						t.Fatalf("attempt %d: expected retry error %q, got %v", attempt+1, expectedRetry, err)
					}
					if !result.IsZero() {
						t.Fatalf("expected controller-runtime backoff, got %#v", result)
					}
					if calls != attempt+1 {
						t.Fatalf("credential calls = %d, want %d", calls, attempt+1)
					}
					if client.statusWriter.updates != 1 {
						t.Fatalf("attempt %d: status updates = %d, want 1", attempt+1, client.statusWriter.updates)
					}
					stored := binding.DeepCopyObject().(crclient.Object)
					if err := fakeClient.Get(ctx, req.NamespacedName, stored); err != nil {
						t.Fatal(err)
					}
					var status string
					switch b := stored.(type) {
					case *msiacrpullv1beta1.AcrPullBinding:
						status = b.Status.Error
					case *msiacrpullv1beta2.AcrPullBinding:
						status = b.Status.Error
					}
					if status != expected {
						t.Fatalf("attempt %d: persisted status = %q, want %q", attempt+1, status, expected)
					}
				}
			})
		}
	}
}

func TestCredentialStatusMessageUsesStructuredServerResponseError(t *testing.T) {
	const body = `{"errors":[{"code":"INTERNAL_ERROR","message":"The registry service is temporarily unavailable"}]}`
	err := credentialGenerationError{
		operation: "failed to retrieve ACR token",
		err: &azcore.ResponseError{
			StatusCode: http.StatusInternalServerError,
			RawResponse: &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader(body)),
			},
		},
	}

	const expected = "failed to retrieve ACR token: request failed with HTTP status 500: INTERNAL_ERROR"
	if status := credentialStatusMessage(err); status != expected {
		t.Fatalf("expected structured status %q, got %q", expected, status)
	}
}

func TestCredentialStatusMessagePreservesUnknownError(t *testing.T) {
	err := credentialGenerationError{
		operation: "failed to retrieve ARM token",
		err:       errors.New("temporary Azure outage"),
	}
	if status := credentialStatusMessage(err); status != err.Error() {
		t.Fatalf("expected original error %q, got %q", err.Error(), status)
	}
}

func TestStatusErrorActionUpdatesDifferentStatus(t *testing.T) {
	binding := &msiacrpullv1beta1.AcrPullBinding{
		Status: msiacrpullv1beta1.AcrPullBindingStatus{Error: "temporary Azure outage"},
	}
	reconciler := &genericReconciler[*msiacrpullv1beta1.AcrPullBinding]{
		GetStatusError: func(binding *msiacrpullv1beta1.AcrPullBinding) string {
			return binding.Status.Error
		},
		UpdateStatusError: func(binding *msiacrpullv1beta1.AcrPullBinding, message string) *msiacrpullv1beta1.AcrPullBinding {
			updated := binding.DeepCopy()
			updated.Status.Error = message
			return updated
		},
	}

	const next = "authentication failed"
	action := reconciler.statusErrorAction(binding, next, true)
	if action.updatePullBindingStatus == nil || action.updatePullBindingStatus.Status.Error != next || action.retryError != next {
		t.Fatalf("expected status update and retry, got %#v", action)
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
	updates int
}

func (w *recordingStatusWriter) Update(ctx context.Context, obj crclient.Object, opts ...crclient.SubResourceUpdateOption) error {
	w.updates++
	w.updated = obj.DeepCopyObject().(crclient.Object)
	if w.SubResourceWriter != nil {
		return w.SubResourceWriter.Update(ctx, obj, opts...)
	}
	return nil
}
