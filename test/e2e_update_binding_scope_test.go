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
	t.Run("v1beta1", func(t *testing.T) {
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

	t.Run("v1beta2", func(t *testing.T) {
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
	getErr    error
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
	if c.conflicts > 0 {
		c.conflicts--
		revision := 3 - c.conflicts
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
