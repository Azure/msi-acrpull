include ./../.bingo/Variables.mk

UNIQUE_INPUT ?= ${USER}-test-dev
LOCATION ?= EastUS

_output/acr-deployment:
	echo "$(UNIQUE_INPUT)-acr" > _output/acr-deployment

_output/acr-infrastructure.json: _output/acr-deployment
	az deployment sub create --name "$(shell cat _output/acr-deployment )" --location "$(LOCATION)" --template-file "./infrastructure/acr.resourceGroup.bicep" --parameters "location=$(LOCATION)" --parameters "uniqueIdentifier=$(UNIQUE_INPUT)" --output "json" > _output/acr-infrastructure.json

_output/aks-deployment:
	echo "$(UNIQUE_INPUT)-aks" > _output/aks-deployment

_output/aks-infrastructure.json: _output/aks-deployment
	az deployment sub create --name "$(shell cat _output/aks-deployment )" --location "$(LOCATION)" --template-file "./infrastructure/aks.resourceGroup.bicep" --parameters "location=$(LOCATION)" --parameters "uniqueIdentifier=$(UNIQUE_INPUT)" --output "json" > _output/aks-infrastructure.json

.PHONY: cleanup-resource-group
cleanup-resource-group:
	test -f _output/acr-infrastructure.json && az group delete --name "$(shell jq --raw-output '.properties.outputs.resourceGroup.value' < _output/acr-infrastructure.json )"
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

.PHONY: mirror-images
mirror-images: _output/acr-infrastructure.json _output/alice _output/bob

_output/alice _output/bob:
	az acr import --name "$(shell jq --raw-output '.properties.outputs.acr.value.registryName.value' < _output/acr-infrastructure.json )" --source "quay.io/fedora/fedora-minimal:latest" --image "$(notdir $@):latest"
	echo "$(shell jq --raw-output '.properties.outputs.acr.value.registryName.value' < _output/acr-infrastructure.json ).azurecr.io/$(notdir $@)@$(shell az acr repository show --name "$(shell jq --raw-output '.properties.outputs.acr.value.registryName.value' < _output/acr-infrastructure.json )" --image $(notdir $@):latest --query digest --output tsv)" > $@

_output/aks.kubeconfig: _output/aks-infrastructure.json
	az aks get-credentials --resource-group "$(shell jq --raw-output '.properties.outputs.resourceGroup.value' < _output/aks-infrastructure.json )" --name "$(shell jq --raw-output '.properties.outputs.aks.value.aks.value' < _output/aks-infrastructure.json )" --admin --file _output/aks.kubeconfig

_output/nodeResourceGroup: _output/aks-infrastructure.json
	az aks show --resource-group "$(shell jq --raw-output '.properties.outputs.resourceGroup.value' < _output/aks-infrastructure.json )" --name "$(shell jq --raw-output '.properties.outputs.aks.value.aks.value' < _output/aks-infrastructure.json )" --query nodeResourceGroup -o tsv > _output/nodeResourceGroup

_output/systemVMSS: _output/nodeResourceGroup
	az vmss list --resource-group "$(shell cat _output/nodeResourceGroup )" --query '[?tags."aks-managed-poolName"==`system`].name' -o tsv > _output/systemVMSS

_output/system-vmss-puller.json: _output/systemVMSS _output/acr-infrastructure.json
	 az vmss identity assign --resource-group "$(shell cat _output/nodeResourceGroup )" --name "$(shell cat _output/systemVMSS )" --identities "$(shell jq --raw-output '.properties.outputs.acr.value.pullerIdentity.value' < _output/acr-infrastructure.json )" > _output/system-vmss-puller.json
	 az vmss update-instances --resource-group "$(shell cat _output/nodeResourceGroup )" --name "$(shell cat _output/systemVMSS )" --instance-ids '*'

_output/image: _output/acr-infrastructure.json
	az acr build --registry "$(shell jq --raw-output '.properties.outputs.acr.value.serviceRegistryName.value' < _output/acr-infrastructure.json )" --image "msi-acrpull:latest" ./../
	echo "$(shell jq --raw-output '.properties.outputs.acr.value.serviceRegistryName.value' < _output/acr-infrastructure.json ).azurecr.io/msi-acrpull@$(shell az acr repository show --name "$(shell jq --raw-output '.properties.outputs.acr.value.serviceRegistryName.value' < _output/acr-infrastructure.json )" --image msi-acrpull:latest --query digest --output tsv)" > _output/image

.PHONY : prometheus-crds
prometheus-crds: _output/assets/0alertmanagerConfigCustomResourceDefinition.yaml _output/assets/0prometheusCustomResourceDefinition.yaml _output/assets/0servicemonitorCustomResourceDefinition.yaml _output/assets/0alertmanagerCustomResourceDefinition.yaml _output/assets/0prometheusagentCustomResourceDefinition.yaml _output/assets/0thanosrulerCustomResourceDefinition.yaml _output/assets/0podmonitorCustomResourceDefinition.yaml _output/assets/0prometheusruleCustomResourceDefinition.yaml _output/assets/namespace.yaml _output/assets/0probeCustomResourceDefinition.yaml _output/assets/0scrapeconfigCustomResourceDefinition.yaml

_output/assets/0alertmanagerConfigCustomResourceDefinition.yaml _output/assets/0prometheusCustomResourceDefinition.yaml _output/assets/0servicemonitorCustomResourceDefinition.yaml _output/assets/0alertmanagerCustomResourceDefinition.yaml _output/assets/0prometheusagentCustomResourceDefinition.yaml _output/assets/0thanosrulerCustomResourceDefinition.yaml _output/assets/0podmonitorCustomResourceDefinition.yaml _output/assets/0prometheusruleCustomResourceDefinition.yaml _output/assets/namespace.yaml _output/assets/0probeCustomResourceDefinition.yaml _output/assets/0scrapeconfigCustomResourceDefinition.yaml:
	mkdir -p $(dir $@)
	wget --output-document=$@ https://raw.githubusercontent.com/prometheus-operator/kube-prometheus/main/manifests/setup/$(notdir $@)

.PHONY: deploy
deploy: _output/aks.kubeconfig _output/image $(KUSTOMIZE) prometheus-crds _output/system-vmss-puller.json
	kubectl --kubeconfig _output/aks.kubeconfig apply --server-side -f _output/assets/
	rm -rf _output/config
	cp -r ./../config _output/config
	$(KUSTOMIZE) build _output/config/crd | kubectl --kubeconfig _output/aks.kubeconfig apply --server-side -f -
	kubectl --kubeconfig _output/aks.kubeconfig wait --for condition=Established crd/acrpullbindings.msi-acrpull.microsoft.com
	pushd _output/config/manager && $(KUSTOMIZE) edit set image controller="$(shell cat _output/image )" && popd
	$(KUSTOMIZE) build _output/config/default | kubectl --kubeconfig _output/aks.kubeconfig apply --server-side -f -
	kubectl --kubeconfig _output/aks.kubeconfig --namespace msi-acrpull-system wait --for condition=Available deployment/msi-acrpull-controller-manager --timeout 120s

.PHONY: test
test: deploy mirror-images
	$(MAKE) test-e2e

.PHONY: test-e2e
test-e2e:
	ALICE_IMAGE="$(shell cat _output/alice )" BOB_IMAGE="$(shell cat _output/bob )" KUBECONFIG="_output/aks.kubeconfig" ACR_FQDN="$(shell jq --raw-output '.properties.outputs.acr.value.registryName.value' < _output/acr-infrastructure.json).azurecr.io" PULLER_ID="$(shell jq --raw-output '.properties.outputs.acr.value.pullerIdentity.value' < _output/acr-infrastructure.json )" LABEL_SELECTOR="agentpool=user" go test -v -tags e2e ./
