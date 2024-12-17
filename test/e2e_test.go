//go:build e2e

package test

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	azworkloadidentity "github.com/Azure/azure-workload-identity/pkg/webhook"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
	msiacrpullv1beta2 "github.com/Azure/msi-acrpull/api/v1beta2"
)

func TestManagedIdentityPulls(t *testing.T) {
	testACRPullBinding[*msiacrpullv1beta1.AcrPullBinding](t, "v1beta1-msi-", func(namespace, name, scope, serviceAccount string, cfg *Config) *msiacrpullv1beta1.AcrPullBinding {
		return &msiacrpullv1beta1.AcrPullBinding{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Spec: msiacrpullv1beta1.AcrPullBindingSpec{
				AcrServer:                 cfg.RegistryFQDN,
				Scope:                     scope,
				ManagedIdentityResourceID: cfg.PullerResourceID,
				ServiceAccountName:        serviceAccount,
			},
		}
	}, false, func(prefix string, cfg *Config, ctx context.Context, client crclient.Client, nodeSelector map[string]string, t *testing.T) {
		t.Run("pulls succeed with acrpullbinding", func(t *testing.T) {
			t.Parallel()

			namespace := prefix + "success"
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
			if err := client.Create(ctx, &msiacrpullv1beta1.AcrPullBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: pullBinding},
				Spec: msiacrpullv1beta1.AcrPullBindingSpec{
					AcrServer:                 cfg.RegistryFQDN,
					ManagedIdentityResourceID: cfg.PullerResourceID,
					ServiceAccountName:        serviceAccount,
				},
			}); err != nil {
				t.Fatalf("failed to create pull binding %s/%s: %v", namespace, pullBinding, err)
			}
			eventuallyFulfillPullBinding[*msiacrpullv1beta1.AcrPullBinding](t, ctx, client, namespace, pullBinding, func(namespace, name string) *msiacrpullv1beta1.AcrPullBinding {
				return &msiacrpullv1beta1.AcrPullBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
				}
			})

			for name, image := range map[string]string{
				"alice": cfg.AliceImage,
				"bob":   cfg.BobImage,
			} {
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					t.Logf("creating pod %s/%s", namespace, name)
					if err := client.Create(ctx, &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{
								Name:            "main",
								Image:           image,
								Command:         []string{"/usr/bin/sleep"},
								Args:            []string{"infinity"},
								ImagePullPolicy: corev1.PullAlways,
							}},
							ServiceAccountName: serviceAccount,
							NodeSelector:       nodeSelector,
						},
					}); err != nil {
						t.Fatalf("failed to create Pod %s/%s: %v", namespace, name, err)
					}

					eventuallyPullImage(t, ctx, client, namespace, name)
				})
			}

			const pod = "fail"
			t.Logf("creating pod without service account %s/%s", namespace, pod)
			if err := client.Create(ctx, &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: pod},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:            "main",
						Image:           cfg.AliceImage,
						Command:         []string{"/usr/bin/sleep"},
						Args:            []string{"infinity"},
						ImagePullPolicy: corev1.PullAlways,
					}},
					NodeSelector: nodeSelector,
				},
			}); err != nil {
				t.Fatalf("failed to create Pod %s: %v", namespace, err)
			}

			eventuallyFailToPullImage(t, ctx, client, namespace, pod)
		})
	})

}

type binding interface {
	*msiacrpullv1beta1.AcrPullBinding | *msiacrpullv1beta2.AcrPullBinding
	crclient.Object
}

// bindingMinter is a constructor for a non-nil pointer to a binding, since we can't create that with `B`
type bindingMinter[B binding] func(namespace, name, scope, serviceAccount string, cfg *Config) B

// bindingGetter fetches a binding using the client, which we can't do since we need a non-nil pointer to the binding for the controller-runtime client
type bindingGetter[B binding] func(client crclient.Client, namespace, name string) func(ctx context.Context) (B, error)

func testACRPullBinding[B binding](
	t *testing.T, prefix string,
	createBinding bindingMinter[B],
	annotateServiceAccount bool,
	extraTests ...func(prefix string, cfg *Config, ctx context.Context, client crclient.Client, nodeSelector map[string]string, t *testing.T)) {
	t.Parallel()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}

	// newBinding is a simple constructor for a binding when we don't care about the content of the object
	newBinding := func(namespace, name string) B {
		return createBinding(namespace, name, "", "", cfg)
	}

	parts := strings.Split(cfg.LabelSelector, "=")
	if len(parts) != 2 {
		t.Fatalf("label selector format is invalid: %q", cfg.LabelSelector)
	}
	nodeSelector := map[string]string{parts[0]: parts[1]}

	client, err := ClientFor(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, interruptCancel := signal.NotifyContext(context.Background(), os.Interrupt)
	t.Cleanup(interruptCancel)
	if deadline, ok := t.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		t.Cleanup(cancel)
	}

	t.Run("pulls fail by default", func(t *testing.T) {
		t.Parallel()

		namespace := prefix + "fail"
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

		const pod = "fail"
		t.Logf("creating pod %s/%s", namespace, pod)
		if err := client.Create(ctx, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: pod},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:            "main",
					Image:           cfg.AliceImage,
					Command:         []string{"/usr/bin/sleep"},
					Args:            []string{"infinity"},
					ImagePullPolicy: corev1.PullAlways,
				}},
				NodeSelector: nodeSelector,
			},
		}); err != nil {
			t.Fatalf("failed to create Pod %s: %v", namespace, err)
		}

		eventuallyFailToPullImage(t, ctx, client, namespace, pod)
	})

	t.Run("removal of acrpullbinding cleans up credentials", func(t *testing.T) {
		t.Parallel()

		namespace := prefix + "mutation"
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
		sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: serviceAccount}}
		if annotateServiceAccount {
			sa.Annotations = map[string]string{
				azworkloadidentity.ClientIDAnnotation: cfg.PullerClientID,
				azworkloadidentity.TenantIDAnnotation: cfg.PullerTenantID,
			}
		}
		t.Logf("creating service account %s/%s", namespace, serviceAccount)
		if err := client.Create(ctx, sa); err != nil && !errors.IsAlreadyExists(err) {
			t.Fatalf("failed to create service account %s/%s: %v", namespace, serviceAccount, err)
		}

		const pullBinding = "pull-binding"
		t.Logf("creating pull binding %s/%s", namespace, pullBinding)
		if err := client.Create(ctx, createBinding(namespace, pullBinding, "repository:alice:pull", serviceAccount, cfg)); err != nil {
			t.Fatalf("failed to create pull binding %s/%s: %v", namespace, pullBinding, err)
		}
		eventuallyFulfillPullBinding[B](t, ctx, client, namespace, pullBinding, newBinding)

		const name = "alice"
		t.Logf("creating pod %s/%s", namespace, name)
		if err := client.Create(ctx, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:            "main",
					Image:           cfg.AliceImage,
					Command:         []string{"/usr/bin/sleep"},
					Args:            []string{"infinity"},
					ImagePullPolicy: corev1.PullAlways,
				}},
				ServiceAccountName: serviceAccount,
				NodeSelector:       nodeSelector,
			},
		}); err != nil {
			t.Fatalf("failed to create Pod %s/%s: %v", namespace, name, err)
		}

		eventuallyPullImage(t, ctx, client, namespace, name)

		if err := client.Delete(ctx, newBinding(namespace, pullBinding)); err != nil {
			t.Fatalf("failed to remove pull binding %s/%s: %v", namespace, pullBinding, err)
		}

		EventuallyObject(t, ctx, fmt.Sprintf("ACRPullBinding %s/%s to be deleted", namespace, pullBinding),
			func(ctx context.Context) (B, error) {
				thisBinding := newBinding(namespace, pullBinding)
				err := client.Get(ctx, crclient.ObjectKeyFromObject(thisBinding), thisBinding)
				if errors.IsNotFound(err) {
					return createBinding("deleted", "deleted", "", "", cfg), nil
				}
				return thisBinding, err
			},
			[]Predicate[B]{
				func(binding B) (done bool, reasons string, err error) {
					done = binding.GetNamespace() == "deleted" && binding.GetName() == "deleted"
					return done, fmt.Sprintf("wanted binding to be gone, got binding %s/%s", binding.GetNamespace(), binding.GetName()), nil
				},
			},
			WithTimeout(2*time.Minute),
		)

		const pod = "fail"
		t.Logf("creating pod with service account after binding deleted %s/%s", namespace, pod)
		if err := client.Create(ctx, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: pod},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:            "main",
					Image:           cfg.AliceImage,
					Command:         []string{"/usr/bin/sleep"},
					Args:            []string{"infinity"},
					ImagePullPolicy: corev1.PullAlways,
				}},
				ServiceAccountName: serviceAccount,
				NodeSelector:       nodeSelector,
			},
		}); err != nil {
			t.Fatalf("failed to create Pod %s: %v", namespace, err)
		}

		eventuallyFailToPullImage(t, ctx, client, namespace, pod)
	})

	t.Run("scoped acrpullbinding only allows pulls within scope", func(t *testing.T) {
		t.Parallel()

		namespace := prefix + "scoped"
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
		if annotateServiceAccount {
			sa.Annotations = map[string]string{
				azworkloadidentity.ClientIDAnnotation: cfg.PullerClientID,
				azworkloadidentity.TenantIDAnnotation: cfg.PullerTenantID,
			}
		}
		if err := client.Create(ctx, sa); err != nil && !errors.IsAlreadyExists(err) {
			t.Fatalf("failed to create service account %s/%s: %v", namespace, serviceAccount, err)
		}

		const pullBinding = "pull-binding"
		t.Logf("creating pull binding %s/%s", namespace, pullBinding)
		if err := client.Create(ctx, createBinding(namespace, pullBinding, "repository:alice:pull", serviceAccount, cfg)); err != nil {
			t.Fatalf("failed to create pull binding %s/%s: %v", namespace, pullBinding, err)
		}
		eventuallyFulfillPullBinding[B](t, ctx, client, namespace, pullBinding, newBinding)

		validateScopedPods(ctx, t, cfg, namespace, serviceAccount, client, nodeSelector)
	})

	for _, test := range extraTests {
		test(prefix, cfg, ctx, client, nodeSelector, t)
	}
}

func validateScopedPods(ctx context.Context, t *testing.T, cfg *Config, namespace, serviceAccount string, client crclient.Client, nodeSelector map[string]string) {
	type imageMeta struct {
		image   string
		succeed bool
	}
	for name, imageCfg := range map[string]imageMeta{
		"alice": {
			image:   cfg.AliceImage,
			succeed: true,
		},
		"bob": {
			image:   cfg.BobImage,
			succeed: false,
		},
	} {
		what := "fails"
		if imageCfg.succeed {
			what = "succeeds"
		}
		t.Run(name+" "+what+" to pull the image", func(t *testing.T) {
			t.Parallel()
			t.Logf("creating pod %s/%s", namespace, name)
			if err := client.Create(ctx, &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:            "main",
						Image:           imageCfg.image,
						Command:         []string{"/usr/bin/sleep"},
						Args:            []string{"infinity"},
						ImagePullPolicy: corev1.PullAlways,
					}},
					ServiceAccountName: serviceAccount,
					NodeSelector:       nodeSelector,
				},
			}); err != nil {
				t.Fatalf("failed to create Pod %s/%s: %v", namespace, name, err)
			}

			if imageCfg.succeed {
				eventuallyPullImage(t, ctx, client, namespace, name)
			} else {
				eventuallyFailToPullImage(t, ctx, client, namespace, name)
			}
		})
	}

	const pod = "fail"
	t.Logf("creating pod without service account %s/%s", namespace, pod)
	if err := client.Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: pod},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "main",
				Image:           cfg.AliceImage,
				Command:         []string{"/usr/bin/sleep"},
				Args:            []string{"infinity"},
				ImagePullPolicy: corev1.PullAlways,
			}},
			NodeSelector: nodeSelector,
		},
	}); err != nil {
		t.Fatalf("failed to create Pod %s: %v", namespace, err)
	}

	eventuallyFailToPullImage(t, ctx, client, namespace, pod)
}

func eventuallyFulfillPullBinding[B binding](t *testing.T, ctx context.Context, client crclient.Client, namespace, name string, newBinding func(namespace, name string) B) {
	EventuallyObject(t, ctx, fmt.Sprintf("ACRPullBinding %s/%s to have credentials propagated", namespace, name),
		func(ctx context.Context) (B, error) {
			thisBinding := newBinding(namespace, name)
			err := client.Get(ctx, crclient.ObjectKeyFromObject(thisBinding), thisBinding)
			return thisBinding, err
		},
		[]Predicate[B]{
			func(binding B) (done bool, reasons string, err error) {
				switch theBinding := any(binding).(type) {
				case *msiacrpullv1beta1.AcrPullBinding:
					done = theBinding.Status.Error == "" && theBinding.Status.LastTokenRefreshTime != nil && theBinding.Status.TokenExpirationTime != nil
					return done, fmt.Sprintf("wanted refresh times to be published without error, got error=%s, refresh=%s, expiration=%s", theBinding.Status.Error, theBinding.Status.LastTokenRefreshTime, theBinding.Status.TokenExpirationTime), nil
				case *msiacrpullv1beta2.AcrPullBinding:
					done = theBinding.Status.Error == "" && theBinding.Status.LastTokenRefreshTime != nil && theBinding.Status.TokenExpirationTime != nil
					return done, fmt.Sprintf("wanted refresh times to be published without error, got error=%s, refresh=%s, expiration=%s", theBinding.Status.Error, theBinding.Status.LastTokenRefreshTime, theBinding.Status.TokenExpirationTime), nil
				default:
					panic(fmt.Errorf("programmer error: got %T in predicate", binding))
				}
			},
		},
		WithTimeout(2*time.Minute),
	)
}

func eventuallyPullImage(t *testing.T, ctx context.Context, client crclient.Client, namespace, name string) {
	EventuallyObject(t, ctx, fmt.Sprintf("Pod %s/%s to pull the image", namespace, name),
		func(ctx context.Context) (*corev1.Pod, error) {
			thisPod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
			err := client.Get(ctx, crclient.ObjectKeyFromObject(&thisPod), &thisPod)
			return &thisPod, err
		},
		[]Predicate[*corev1.Pod]{
			PodPhasePredicate(corev1.PodRunning),
			ConditionPredicate[*corev1.Pod](Condition{
				Type:   string(corev1.PodReady),
				Status: metav1.ConditionTrue,
			}),
		},
		WithTimeout(2*time.Minute),
	)
}

func eventuallyFailToPullImage(t *testing.T, ctx context.Context, client crclient.Client, namespace, name string) {
	EventuallyObject(t, ctx, fmt.Sprintf("Pod %s/%s to fail to pull the image", namespace, name),
		func(ctx context.Context) (*corev1.Pod, error) {
			thisPod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
			err := client.Get(ctx, crclient.ObjectKeyFromObject(&thisPod), &thisPod)
			return &thisPod, err
		},
		[]Predicate[*corev1.Pod]{
			PodPhasePredicate(corev1.PodPending),
			ConditionPredicate[*corev1.Pod](Condition{
				Type:   string(corev1.PodReady),
				Status: metav1.ConditionFalse,
				Reason: "ContainersNotReady",
			}),
			ContainerStatePredicate("main", ContainerStateMatcher{
				State:  ContainerStateWaiting,
				Reason: "ImagePullBackOff",
			}),
		},
		WithTimeout(2*time.Minute),
	)
}

// PodPhasePredicate returns a predicate that validates that a pod is in the requisite phase.
func PodPhasePredicate(wanted corev1.PodPhase) Predicate[*corev1.Pod] {
	return func(pod *corev1.Pod) (done bool, reasons string, err error) {
		got := pod.Status.Phase
		prefix := ""
		if got != wanted {
			prefix = "in"
		}
		return got == wanted, fmt.Sprintf("%scorrect phase: wanted %s, got %s", prefix, wanted, got), nil
	}
}

type ContainerState string

const (
	ContainerStateWaiting    ContainerState = "Waiting"
	ContainerStateRunning    ContainerState = "Running"
	ContainerStateTerminated ContainerState = "Terminated"
)

type ContainerStateMatcher struct {
	State   ContainerState
	Reason  string
	Message string
}

func (m ContainerStateMatcher) Matches(state corev1.ContainerState) bool {
	switch m.State {
	case ContainerStateWaiting:
		if state.Waiting == nil {
			return false
		}
		if m.Reason != "" && state.Waiting.Reason != m.Reason {
			return false
		}
		if m.Message != "" && state.Waiting.Message != m.Message {
			return false
		}
	case ContainerStateRunning:
		if state.Running == nil {
			return false
		}
	case ContainerStateTerminated:
		if state.Terminated == nil {
			return false
		}
		if m.Reason != "" && state.Terminated.Reason != m.Reason {
			return false
		}
		if m.Message != "" && state.Terminated.Message != m.Message {
			return false
		}
	default:
		panic(fmt.Sprintf("programmer error: unexpected state: %v", m.State))
	}
	return true
}

func (m ContainerStateMatcher) String() string {
	msg := string(m.State)
	if m.Reason != "" {
		msg += ": " + m.Reason
	}
	if m.Message != "" {
		msg += "(" + m.Message + ")"
	}
	return msg
}

func FormatContainerState(state corev1.ContainerState) string {
	mock := ContainerStateMatcher{}
	if state.Waiting != nil {
		mock.State = ContainerStateWaiting
		mock.Reason = state.Waiting.Reason
		mock.Message = state.Waiting.Message
	} else if state.Running != nil {
		mock.State = ContainerStateRunning
	} else if state.Terminated != nil {
		mock.State = ContainerStateTerminated
		mock.Reason = state.Terminated.Reason
		mock.Message = state.Terminated.Message
	}
	return mock.String()
}

func ContainerStatePredicate(containerName string, wanted ContainerStateMatcher) Predicate[*corev1.Pod] {
	return func(pod *corev1.Pod) (done bool, reason string, err error) {
		for _, containerStatus := range pod.Status.ContainerStatuses {
			if containerStatus.Name == containerName {
				matches := wanted.Matches(containerStatus.State)
				prefix := ""
				if !matches {
					prefix = "in"
				}
				return matches, fmt.Sprintf("%scorrect container status for %s, wanted %s, got %s", prefix, containerName, wanted, FormatContainerState(containerStatus.State)), nil
			}
		}
		return false, fmt.Sprintf("container status for %s not found, wanted %s", containerName, wanted), nil
	}
}
