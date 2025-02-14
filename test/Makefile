include ./../.bingo/Variables.mk

UNIQUE_INPUT ?= ${USER}-test-dev
LOCATION ?= EastUS

_output:
	mkdir _output

_output/tenant: _output/
	az account show --query tenantId --output tsv > $@

_output/deployment: _output
	echo -n "$(UNIQUE_INPUT)" | sha256sum | awk '{print $$1}' > _output/deployment

_output/infrastructure.json: _output/deployment
	az deployment sub create --name "$(shell cat _output/deployment )" --location "$(LOCATION)" --template-file "./infrastructure/resourceGroup.bicep" --parameters "location=$(LOCATION)" --parameters "uniqueIdentifier=$(UNIQUE_INPUT)" --output "json" > _output/infrastructure.json

_output/identity.json: _output
	az deployment sub create --name msi-acrpull-e2e-test-runner --template-file "./infrastructure/identity.resourceGroup.bicep" --parameters "location=$(LOCATION)" --output json --location "$(LOCATION)" > _output/identity.json

.PHONY: cleanup-resource-group
cleanup-resource-group:
	test -f _output/infrastructure.json && az group delete --yes --name "$(shell jq --raw-output '.properties.outputs.resourceGroup.value' < _output/infrastructure.json )"
	rm _output/infrastructure.json

.PHONY: cleanup-deployment
cleanup-deployment:
	test -f _output/deployment && az deployment sub delete --name "$(shell cat _output/deployment )"
	rm _output/deployment

.PHONY: cleanup
cleanup: cleanup-resource-group cleanup-deployment

_output/alice.json _output/bob.json: _output/infrastructure.json
	az acr import --name "$(shell jq --raw-output '.properties.outputs.acr.value.registryName.value' < _output/infrastructure.json )" --source "quay.io/fedora/fedora-minimal:latest" --image "$(basename $(notdir $@)):latest"
	az acr repository show --name "$(shell jq --raw-output '.properties.outputs.acr.value.registryName.value' < _output/infrastructure.json )" --image $(basename $(notdir $@)):latest --output json > $@

_output/alice: _output/alice.json
	echo "$(shell jq --raw-output '.properties.outputs.acr.value.registryName.value' < _output/infrastructure.json ).azurecr.io/$(notdir $@)@$(shell jq --raw-output '.digest' < $@.json)" > $@

_output/bob: _output/bob.json
	echo "$(shell jq --raw-output '.properties.outputs.acr.value.registryName.value' < _output/infrastructure.json ).azurecr.io/$(notdir $@)@$(shell jq --raw-output '.digest' < $@.json)" > $@

_output/aks.kubeconfig: _output/infrastructure.json
	az aks get-credentials --overwrite-existing --resource-group "$(shell jq --raw-output '.properties.outputs.resourceGroup.value' < _output/infrastructure.json )" --name "$(shell jq --raw-output '.properties.outputs.aks.value.aks.value' < _output/infrastructure.json )" --admin --file _output/aks.kubeconfig

_output/nodeResourceGroup: _output/infrastructure.json
	az aks show --resource-group "$(shell jq --raw-output '.properties.outputs.resourceGroup.value' < _output/infrastructure.json )" --name "$(shell jq --raw-output '.properties.outputs.aks.value.aks.value' < _output/infrastructure.json )" --query nodeResourceGroup -o tsv > _output/nodeResourceGroup

_output/systemVMSS: _output/nodeResourceGroup
	az vmss list --resource-group "$(shell cat _output/nodeResourceGroup )" --query '[?tags."aks-managed-poolName"==`system`].name' -o tsv > _output/systemVMSS

_output/system-vmss-puller.json: _output/systemVMSS _output/infrastructure.json
	 az vmss identity assign --resource-group "$(shell cat _output/nodeResourceGroup )" --name "$(shell cat _output/systemVMSS )" --identities "$(shell jq --raw-output '.properties.outputs.acr.value.pullerIdentity.value' < _output/infrastructure.json )" > _output/system-vmss-puller.json
	 az vmss update-instances --resource-group "$(shell cat _output/nodeResourceGroup )" --name "$(shell cat _output/systemVMSS )" --instance-ids '*'

_output/image.json: _output/infrastructure.json
	az acr build --registry "$(shell jq --raw-output '.properties.outputs.acr.value.serviceRegistryName.value' < _output/infrastructure.json )" --image "msi-acrpull:latest" ./../
	az acr repository show --name "$(shell jq --raw-output '.properties.outputs.acr.value.serviceRegistryName.value' < _output/infrastructure.json )" --image msi-acrpull:latest --output json > _output/image.json

_output/image: _output/image.json
	echo "$(shell jq --raw-output '.properties.outputs.acr.value.serviceRegistryName.value' < _output/infrastructure.json ).azurecr.io/msi-acrpull@$(shell jq --raw-output '.digest' _output/image.json )" > _output/image

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

_output/deploy/new-image: _output/deploy/image
	touch $@

_output/deploy/image: _output/image
_output/deploy/image: _output/aks.kubeconfig $(HELM) _output/deploy/prometheus-crds _output/system-vmss-puller.json
	cp values.template.yaml _output/values.yaml
	sed -i -e 's|IMAGE_DIGEST|$(shell cat _output/$(notdir $@) )|' _output/values.yaml
	$(HELM) template --kubeconfig _output/aks.kubeconfig acrpull ./../config/helm --values _output/values.yaml --create-namespace --dry-run=server > _output/chart.yaml
	kubectl --kubeconfig _output/aks.kubeconfig apply --server-side -f _output/chart.yaml
	kubectl --kubeconfig _output/aks.kubeconfig wait --for condition=Established crd/acrpullbindings.msi-acrpull.microsoft.com
	kubectl --kubeconfig _output/aks.kubeconfig wait --for condition=Established crd/acrpullbindings.acrpull.microsoft.com
	kubectl --kubeconfig _output/aks.kubeconfig --namespace acrpull wait --for condition=Available deployment/acrpull --timeout 120s
	touch $@

deploy:
	cp values.template.yaml _output/values.yaml
	sed -i -e 's|IMAGE_DIGEST|$(shell cat _output/image )|' _output/values.yaml
	$(HELM) template --kubeconfig _output/aks.kubeconfig acrpull ./../config/helm --values _output/values.yaml --create-namespace --dry-run=server > _output/chart.yaml
	kubectl --kubeconfig _output/aks.kubeconfig apply --server-side -f _output/chart.yaml
	kubectl --kubeconfig _output/aks.kubeconfig wait --for condition=Established crd/acrpullbindings.msi-acrpull.microsoft.com
	kubectl --kubeconfig _output/aks.kubeconfig wait --for condition=Established crd/acrpullbindings.acrpull.microsoft.com
	kubectl --kubeconfig _output/aks.kubeconfig --namespace acrpull wait --for condition=Available deployment/acrpull --timeout 120s

.PHONY: test
test: _output/deploy/new-image _output/alice _output/bob _output/tenant
	$(MAKE) test-e2e

.PHONY: test-e2e
test-e2e:
	ALICE_IMAGE="$(shell cat _output/alice )" BOB_IMAGE="$(shell cat _output/bob )" KUBECONFIG="_output/aks.kubeconfig" ACR_FQDN="$(shell jq --raw-output '.properties.outputs.acr.value.registryName.value' < _output/infrastructure.json).azurecr.io" PULLER_ID="$(shell jq --raw-output '.properties.outputs.acr.value.pullerIdentity.value' < _output/infrastructure.json )" PULLER_CLIENT_ID="$(shell jq --raw-output '.properties.outputs.acr.value.pullerIdentityClientId.value' < _output/infrastructure.json )" PULLER_TENANT_ID="$(shell cat _output/tenant)" LABEL_SELECTOR="agentpool=user" go test -v -tags e2e ./ $(GOTESTFLAGS)
