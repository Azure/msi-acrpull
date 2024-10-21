include ./../.bingo/Variables.mk

UNIQUE_INPUT ?= ${USER}-test-dev
LOCATION ?= EastUS

_output:
	mkdir _output

_output/acr-deployment: _output
	echo -n "$(UNIQUE_INPUT)-acr" | sha256sum | awk '{print $$1}' > _output/acr-deployment

_output/acr-infrastructure.json: _output/acr-deployment
	az deployment sub create --name "$(shell cat _output/acr-deployment )" --location "$(LOCATION)" --template-file "./infrastructure/acr.resourceGroup.bicep" --parameters "location=$(LOCATION)" --parameters "uniqueIdentifier=$(UNIQUE_INPUT)" --output "json" > _output/acr-infrastructure.json

_output/aks-deployment: _output
	echo -n "$(UNIQUE_INPUT)-aks" | sha256sum | awk '{print $$1}' > _output/aks-deployment

_output/aks-infrastructure.json: _output/aks-deployment
	az deployment sub create --name "$(shell cat _output/aks-deployment )" --location "$(LOCATION)" --template-file "./infrastructure/aks.resourceGroup.bicep" --parameters "location=$(LOCATION)" --parameters "uniqueIdentifier=$(UNIQUE_INPUT)" --output "json" > _output/aks-infrastructure.json

_output/identity.json: _output
	az deployment sub create --name msi-acrpull-e2e-test-runner --template-file "./infrastructure/identity.resourceGroup.bicep" --parameters "location=$(LOCATION)" --output json --location "$(LOCATION)" > _output/identity.json

.PHONY: cleanup-resource-group
cleanup-resource-group:
	test -f _output/acr-infrastructure.json && az group delete --yes --name "$(shell jq --raw-output '.properties.outputs.resourceGroup.value' < _output/acr-infrastructure.json )"
	rm _output/acr-infrastructure.json
	rm _output/aks-infrastructure.json

.PHONY: cleanup-deployment
cleanup-deployment:
	test -f _output/acr-deployment && az deployment sub delete --name "$(shell cat _output/acr-deployment )"
	rm _output/acr-deployment
	test -f _output/aks-deployment && az deployment sub delete --name "$(shell cat _output/aks-deployment )"
	rm _output/aks-deployment

.PHONY: cleanup
cleanup: cleanup-resource-group cleanup-deployment

_output/alice.json _output/bob.json: _output/acr-infrastructure.json
	az acr import --name "$(shell jq --raw-output '.properties.outputs.acr.value.registryName.value' < _output/acr-infrastructure.json )" --source "quay.io/fedora/fedora-minimal:latest" --image "$(basename $(notdir $@)):latest"
	az acr repository show --name "$(shell jq --raw-output '.properties.outputs.acr.value.registryName.value' < _output/acr-infrastructure.json )" --image $(basename $(notdir $@)):latest --output json > $@

_output/alice: _output/alice.json
	echo "$(shell jq --raw-output '.properties.outputs.acr.value.registryName.value' < _output/acr-infrastructure.json ).azurecr.io/$(notdir $@)@$(shell jq --raw-output '.digest' < $@.json)" > $@

_output/bob: _output/bob.json
	echo "$(shell jq --raw-output '.properties.outputs.acr.value.registryName.value' < _output/acr-infrastructure.json ).azurecr.io/$(notdir $@)@$(shell jq --raw-output '.digest' < $@.json)" > $@

_output/aks.kubeconfig: _output/aks-infrastructure.json
	az aks get-credentials --resource-group "$(shell jq --raw-output '.properties.outputs.resourceGroup.value' < _output/aks-infrastructure.json )" --name "$(shell jq --raw-output '.properties.outputs.aks.value.aks.value' < _output/aks-infrastructure.json )" --admin --file _output/aks.kubeconfig

_output/nodeResourceGroup: _output/aks-infrastructure.json
	az aks show --resource-group "$(shell jq --raw-output '.properties.outputs.resourceGroup.value' < _output/aks-infrastructure.json )" --name "$(shell jq --raw-output '.properties.outputs.aks.value.aks.value' < _output/aks-infrastructure.json )" --query nodeResourceGroup -o tsv > _output/nodeResourceGroup

_output/systemVMSS: _output/nodeResourceGroup
	az vmss list --resource-group "$(shell cat _output/nodeResourceGroup )" --query '[?tags."aks-managed-poolName"==`system`].name' -o tsv > _output/systemVMSS

_output/system-vmss-puller.json: _output/systemVMSS _output/acr-infrastructure.json
	 az vmss identity assign --resource-group "$(shell cat _output/nodeResourceGroup )" --name "$(shell cat _output/systemVMSS )" --identities "$(shell jq --raw-output '.properties.outputs.acr.value.pullerIdentity.value' < _output/acr-infrastructure.json )" > _output/system-vmss-puller.json
	 az vmss update-instances --resource-group "$(shell cat _output/nodeResourceGroup )" --name "$(shell cat _output/systemVMSS )" --instance-ids '*'

_output/image.json: _output/acr-infrastructure.json
	az acr build --registry "$(shell jq --raw-output '.properties.outputs.acr.value.serviceRegistryName.value' < _output/acr-infrastructure.json )" --image "msi-acrpull:latest" ./../
	az acr repository show --name "$(shell jq --raw-output '.properties.outputs.acr.value.serviceRegistryName.value' < _output/acr-infrastructure.json )" --image msi-acrpull:latest --output json > _output/image.json

_output/image: _output/image.json
	echo "$(shell jq --raw-output '.properties.outputs.acr.value.serviceRegistryName.value' < _output/acr-infrastructure.json ).azurecr.io/msi-acrpull@$(shell jq --raw-output '.digest' _output/image.json )" > _output/image

# this is a nasty hack, ideally we'd have some centrally-available ACR to pull old images from
PREVIOUS_TAG=$(shell git describe --tags --abbrev=0)
_output/previous-repo:
	git clone https://github.com/Azure/msi-acrpull.git _output/previous-repo
	cd _output/previous-repo && git checkout "$(PREVIOUS_TAG)"

_output/previous-image.json: _output/acr-infrastructure.json _output/previous-repo
	az acr build --registry "$(shell jq --raw-output '.properties.outputs.acr.value.serviceRegistryName.value' < _output/acr-infrastructure.json )" --image "msi-acrpull:$(PREVIOUS_TAG)" _output/previous-repo
	az acr repository show --name "$(shell jq --raw-output '.properties.outputs.acr.value.serviceRegistryName.value' < _output/acr-infrastructure.json )" --image "msi-acrpull:$(PREVIOUS_TAG)" --output json > _output/previous-image.json

_output/previous-image: _output/previous-image.json
	echo "$(shell jq --raw-output '.properties.outputs.acr.value.serviceRegistryName.value' < _output/acr-infrastructure.json ).azurecr.io/msi-acrpull@$(shell jq --raw-output '.digest' _output/previous-image.json )" > _output/previous-image

prometheus-crds: _output/assets/0alertmanagerConfigCustomResourceDefinition.yaml _output/assets/0prometheusCustomResourceDefinition.yaml _output/assets/0servicemonitorCustomResourceDefinition.yaml _output/assets/0alertmanagerCustomResourceDefinition.yaml _output/assets/0prometheusagentCustomResourceDefinition.yaml _output/assets/0thanosrulerCustomResourceDefinition.yaml _output/assets/0podmonitorCustomResourceDefinition.yaml _output/assets/0prometheusruleCustomResourceDefinition.yaml _output/assets/namespace.yaml _output/assets/0probeCustomResourceDefinition.yaml _output/assets/0scrapeconfigCustomResourceDefinition.yaml

_output/assets/0alertmanagerConfigCustomResourceDefinition.yaml _output/assets/0prometheusCustomResourceDefinition.yaml _output/assets/0servicemonitorCustomResourceDefinition.yaml _output/assets/0alertmanagerCustomResourceDefinition.yaml _output/assets/0prometheusagentCustomResourceDefinition.yaml _output/assets/0thanosrulerCustomResourceDefinition.yaml _output/assets/0podmonitorCustomResourceDefinition.yaml _output/assets/0prometheusruleCustomResourceDefinition.yaml _output/assets/namespace.yaml _output/assets/0probeCustomResourceDefinition.yaml _output/assets/0scrapeconfigCustomResourceDefinition.yaml:
	mkdir -p $(dir $@)
	wget --quiet --output-document=$@ https://raw.githubusercontent.com/prometheus-operator/kube-prometheus/main/manifests/setup/$(notdir $@)

_output/deploy: _output
	mkdir -p _output/deploy

_output/deploy/prometheus-crds: _output/deploy prometheus-crds _output/aks.kubeconfig
	kubectl --kubeconfig _output/aks.kubeconfig apply --server-side -f _output/assets/
	touch $@

_output/config:
	rm -rf _output/config
	cp -r ./../config _output/config

_output/deploy/crd: _output/aks.kubeconfig _output/config $(KUSTOMIZE) _output/deploy
	$(KUSTOMIZE) build _output/config/crd | kubectl --kubeconfig _output/aks.kubeconfig apply --server-side -f -
	kubectl --kubeconfig _output/aks.kubeconfig wait --for condition=Established crd/acrpullbindings.msi-acrpull.microsoft.com
	touch $@

_output/deploy/image: _output/image _output/deploy/previous
_output/deploy/previous-image: _output/previous-image
_output/deploy/image _output/deploy/previous-image: _output/aks.kubeconfig $(KUSTOMIZE) _output/deploy/prometheus-crds _output/system-vmss-puller.json _output/deploy/crd
	cd _output/config/manager && $(KUSTOMIZE) edit set image controller="$(shell cat _output/$(notdir $@) )" && cd -
	$(KUSTOMIZE) build _output/config/default | kubectl --kubeconfig _output/aks.kubeconfig apply --server-side -f -
	kubectl --kubeconfig _output/aks.kubeconfig --namespace msi-acrpull-system wait --for condition=Available deployment/msi-acrpull-controller-manager --timeout 120s
	touch $@

_output/deploy/previous: _output/deploy/previous-image _output/system-vmss-puller.json
	cp pullbinding.template.yaml _output/pullbinding.yaml
	sed -i -e 's|MANAGED_IDENTITY_RESOURCE_ID|$(shell jq --raw-output '.properties.outputs.acr.value.pullerIdentity.value' < _output/acr-infrastructure.json )|g' -e 's|ACR_SERVER|$(shell jq --raw-output '.properties.outputs.acr.value.registryName.value' < _output/acr-infrastructure.json).azurecr.io|g' _output/pullbinding.yaml
	kubectl --kubeconfig _output/aks.kubeconfig apply -f _output/pullbinding.yaml
	kubectl --kubeconfig _output/aks.kubeconfig wait --for 'jsonpath={.imagePullSecrets[0]}' --namespace default serviceaccount/default
	touch $@

.PHONY: test
test: _output/deploy/image _output/alice _output/bob
	$(MAKE) test-e2e

.PHONY: test-e2e
test-e2e:
	ALICE_IMAGE="$(shell cat _output/alice )" BOB_IMAGE="$(shell cat _output/bob )" KUBECONFIG="_output/aks.kubeconfig" ACR_FQDN="$(shell jq --raw-output '.properties.outputs.acr.value.registryName.value' < _output/acr-infrastructure.json).azurecr.io" PULLER_ID="$(shell jq --raw-output '.properties.outputs.acr.value.pullerIdentity.value' < _output/acr-infrastructure.json )" LABEL_SELECTOR="agentpool=user" go test -v -tags e2e ./
