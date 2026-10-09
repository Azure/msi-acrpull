package test

import (
	"context"
	"fmt"

	msiacrpullv1beta1 "github.com/Azure/msi-acrpull/api/v1beta1"
	msiacrpullv1beta2 "github.com/Azure/msi-acrpull/api/v1beta2"
	"k8s.io/client-go/util/retry"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type binding interface {
	*msiacrpullv1beta1.AcrPullBinding | *msiacrpullv1beta2.AcrPullBinding
	crclient.Object
}

func updateBindingScope[B binding](
	ctx context.Context,
	client crclient.Client,
	namespace, name, scope string,
	newBinding func(namespace, name string) B,
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := newBinding(namespace, name)
		if err := client.Get(ctx, crclient.ObjectKeyFromObject(current), current); err != nil {
			return err
		}

		switch binding := any(current).(type) {
		case *msiacrpullv1beta1.AcrPullBinding:
			binding.Spec.Scope = scope
		case *msiacrpullv1beta2.AcrPullBinding:
			binding.Spec.ACR.Scope = scope
		default:
			return fmt.Errorf("unsupported binding type %T", current)
		}

		return client.Update(ctx, current)
	})
}
