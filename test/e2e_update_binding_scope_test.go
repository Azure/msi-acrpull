//go:build e2e

package test

import (
	"context"
	stderrors "errors"
	"fmt"
	"strconv"
	"testing"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
	msiacrpullv1beta2 "github.com/Azure/msi-acrpull/api/v1beta2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func TestUpdateBindingScope(t *testing.T) {
	t.Run("happy path updates without retry", func(t *testing.T) {
		current := &msiacrpullv1beta1.AcrPullBinding{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "test",
				Name:            "binding",
				ResourceVersion: "1",
			},
			Spec: msiacrpullv1beta1.AcrPullBindingSpec{
				Scope: "repository:old:pull",
			},
		}
		client := &scopeUpdateClient{current: current}

		err := updateBindingScope(context.Background(), client, "test", "binding", "repository:alice:pull",
			func(namespace, name string) *msiacrpullv1beta1.AcrPullBinding {
				return &msiacrpullv1beta1.AcrPullBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
			})
		if err != nil {
			t.Fatalf("update binding scope: %v", err)
		}

		if client.gets != 1 || client.updates != 1 {
			t.Fatalf("calls = Get:%d Update:%d, want Get:1 Update:1", client.gets, client.updates)
		}
		updated := client.updated.(*msiacrpullv1beta1.AcrPullBinding)
		if updated.Spec.Scope != "repository:alice:pull" {
			t.Fatalf("scope = %q, want %q", updated.Spec.Scope, "repository:alice:pull")
		}
	})

	t.Run("v1beta1 retries conflicts", func(t *testing.T) {
		current := &msiacrpullv1beta1.AcrPullBinding{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "test",
				Name:            "binding",
				ResourceVersion: "1",
				Labels:          map[string]string{"preserved": "label"},
				Annotations:     map[string]string{"preserved": "annotation"},
			},
			Spec: msiacrpullv1beta1.AcrPullBindingSpec{
				AcrServer:                 "example.azurecr.io",
				Scope:                     "repository:old:pull",
				ManagedIdentityResourceID: "identity",
				ServiceAccountName:        "service-account",
			},
			Status: msiacrpullv1beta1.AcrPullBindingStatus{Error: "initial"},
		}
		client := &scopeUpdateClient{current: current, conflicts: 2}

		err := updateBindingScope(context.Background(), client, "test", "binding", "repository:alice:pull",
			func(namespace, name string) *msiacrpullv1beta1.AcrPullBinding {
				return &msiacrpullv1beta1.AcrPullBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
			})
		if err != nil {
			t.Fatalf("update binding scope: %v", err)
		}

		updated := client.updated.(*msiacrpullv1beta1.AcrPullBinding)
		if updated.Spec.Scope != "repository:alice:pull" {
			t.Fatalf("scope = %q, want %q", updated.Spec.Scope, "repository:alice:pull")
		}
		assertConcurrentChangesPreserved(t, client, updated)
	})

	t.Run("v1beta2 retries conflicts", func(t *testing.T) {
		current := &msiacrpullv1beta2.AcrPullBinding{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "test",
				Name:            "binding",
				ResourceVersion: "1",
				Labels:          map[string]string{"preserved": "label"},
				Annotations:     map[string]string{"preserved": "annotation"},
			},
			Spec: msiacrpullv1beta2.AcrPullBindingSpec{
				ACR: msiacrpullv1beta2.AcrConfiguration{
					Server:      "example.azurecr.io",
					Scope:       "repository:old:pull",
					Environment: msiacrpullv1beta2.AzureEnvironmentPublicCloud,
				},
				Auth: msiacrpullv1beta2.AuthenticationMethod{
					ManagedIdentity: &msiacrpullv1beta2.ManagedIdentityAuth{ResourceID: "identity"},
				},
				ServiceAccountName: "service-account",
			},
			Status: msiacrpullv1beta2.AcrPullBindingStatus{Error: "initial"},
		}
		client := &scopeUpdateClient{current: current, conflicts: 2}

		err := updateBindingScope(context.Background(), client, "test", "binding", "repository:alice:pull",
			func(namespace, name string) *msiacrpullv1beta2.AcrPullBinding {
				return &msiacrpullv1beta2.AcrPullBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
			})
		if err != nil {
			t.Fatalf("update binding scope: %v", err)
		}

		updated := client.updated.(*msiacrpullv1beta2.AcrPullBinding)
		if updated.Spec.ACR.Scope != "repository:alice:pull" {
			t.Fatalf("scope = %q, want %q", updated.Spec.ACR.Scope, "repository:alice:pull")
		}
		assertConcurrentChangesPreserved(t, client, updated)
	})

	t.Run("sad path returns exhausted conflict retries", func(t *testing.T) {
		current := &msiacrpullv1beta1.AcrPullBinding{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "test",
				Name:            "binding",
				ResourceVersion: "1",
				Annotations:     map[string]string{},
			},
		}
		client := &scopeUpdateClient{current: current, conflicts: 100}

		err := updateBindingScope(context.Background(), client, "test", "binding", "repository:alice:pull",
			func(namespace, name string) *msiacrpullv1beta1.AcrPullBinding {
				return &msiacrpullv1beta1.AcrPullBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
			})

		if !apierrors.IsConflict(err) {
			t.Fatalf("error = %v, want Conflict", err)
		}
		if client.gets < 2 || client.updates != client.gets {
			t.Fatalf("calls = Get:%d Update:%d, want multiple matching attempts", client.gets, client.updates)
		}
		if client.updated != nil {
			t.Fatalf("unexpected successful update: %T", client.updated)
		}
	})
}

func TestUpdateBindingScopeDoesNotRetryNonConflictErrors(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		updateErr error
	}{
		{
			name:      "client failure",
			updateErr: apierrors.NewBadRequest("invalid binding update"),
		},
		{
			name:      "server failure",
			updateErr: apierrors.NewInternalError(stderrors.New("API server unavailable")),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			current := &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "test",
					Name:            "binding",
					ResourceVersion: "1",
				},
			}
			client := &scopeUpdateClient{current: current, updateErr: testCase.updateErr}

			err := updateBindingScope(context.Background(), client, "test", "binding", "repository:alice:pull",
				func(namespace, name string) *msiacrpullv1beta1.AcrPullBinding {
					return &msiacrpullv1beta1.AcrPullBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
				})

			if !stderrors.Is(err, testCase.updateErr) {
				t.Fatalf("error = %v, want %v", err, testCase.updateErr)
			}
			if client.gets != 1 || client.updates != 1 {
				t.Fatalf("calls = Get:%d Update:%d, want Get:1 Update:1", client.gets, client.updates)
			}
		})
	}
}

func TestUpdateBindingScopeReturnsGetErrors(t *testing.T) {
	notFound := apierrors.NewNotFound(
		schema.GroupResource{Group: msiacrpullv1beta1.GroupVersion.Group, Resource: "acrpullbindings"},
		"binding",
	)
	client := &scopeUpdateClient{getErr: notFound}

	err := updateBindingScope(context.Background(), client, "test", "binding", "repository:alice:pull",
		func(namespace, name string) *msiacrpullv1beta1.AcrPullBinding {
			return &msiacrpullv1beta1.AcrPullBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
		})

	if !apierrors.IsNotFound(err) {
		t.Fatalf("error = %v, want NotFound", err)
	}
	if client.gets != 1 {
		t.Fatalf("Get calls = %d, want 1", client.gets)
	}
}

func assertConcurrentChangesPreserved(t *testing.T, client *scopeUpdateClient, updated crclient.Object) {
	t.Helper()

	if client.gets != 3 {
		t.Fatalf("Get calls = %d, want 3", client.gets)
	}
	if updated.GetResourceVersion() != "3" {
		t.Fatalf("resourceVersion = %q, want %q", updated.GetResourceVersion(), "3")
	}
	if updated.GetLabels()["preserved"] != "label" {
		t.Fatalf("labels were not preserved: %#v", updated.GetLabels())
	}
	if updated.GetAnnotations()["preserved"] != "annotation" || updated.GetAnnotations()["concurrent"] != "3" {
		t.Fatalf("annotations were not preserved: %#v", updated.GetAnnotations())
	}

	switch binding := updated.(type) {
	case *msiacrpullv1beta1.AcrPullBinding:
		if binding.Status.Error != "concurrent-3" {
			t.Fatalf("status was not preserved: %#v", binding.Status)
		}
	case *msiacrpullv1beta2.AcrPullBinding:
		if binding.Status.Error != "concurrent-3" {
			t.Fatalf("status was not preserved: %#v", binding.Status)
		}
	default:
		t.Fatalf("unexpected binding type %T", updated)
	}
}

type scopeUpdateClient struct {
	crclient.Client
	current   crclient.Object
	updated   crclient.Object
	conflicts int
	gets      int
	updates   int
	getErr    error
	updateErr error
}

func (c *scopeUpdateClient) Get(_ context.Context, _ crclient.ObjectKey, obj crclient.Object, _ ...crclient.GetOption) error {
	c.gets++
	if c.getErr != nil {
		return c.getErr
	}

	switch target := obj.(type) {
	case *msiacrpullv1beta1.AcrPullBinding:
		*target = *c.current.(*msiacrpullv1beta1.AcrPullBinding).DeepCopy()
	case *msiacrpullv1beta2.AcrPullBinding:
		*target = *c.current.(*msiacrpullv1beta2.AcrPullBinding).DeepCopy()
	default:
		return fmt.Errorf("unexpected binding type %T", obj)
	}
	return nil
}

func (c *scopeUpdateClient) Update(_ context.Context, obj crclient.Object, _ ...crclient.UpdateOption) error {
	c.updates++
	if c.updateErr != nil {
		return c.updateErr
	}
	if c.conflicts > 0 {
		c.conflicts--
		revision := c.updates + 1
		c.applyConcurrentUpdate(revision)
		return apierrors.NewConflict(
			schema.GroupResource{Group: "acrpull.microsoft.com", Resource: "acrpullbindings"},
			obj.GetName(),
			stderrors.New("the object has been modified"),
		)
	}

	c.updated = obj.DeepCopyObject().(crclient.Object)
	return nil
}

func (c *scopeUpdateClient) applyConcurrentUpdate(revision int) {
	annotation := strconv.Itoa(revision)
	resourceVersion := annotation
	statusError := "concurrent-" + annotation

	switch binding := c.current.(type) {
	case *msiacrpullv1beta1.AcrPullBinding:
		binding.ResourceVersion = resourceVersion
		binding.Annotations["concurrent"] = annotation
		binding.Status.Error = statusError
	case *msiacrpullv1beta2.AcrPullBinding:
		binding.ResourceVersion = resourceVersion
		binding.Annotations["concurrent"] = annotation
		binding.Status.Error = statusError
	}
}
