#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

echo "docker login to ${MCR_REGISTRY}"
docker login ${MCR_REGISTRY} -u ${MCR_USERNAME} -p ${MCR_PASSWORD}

TAG=${TAG:-$BUILD_NUMBER}
echo "image tag will be ${TAG}"

export IMG="${MCR_REGISTRY}/public/aks/${APP}:${TAG}"
make docker-build
make docker-push

# push to latest tag as well
export IMG="${MCR_REGISTRY}/public/aks/${APP}:latest"
docker tag "${MCR_REGISTRY}/public/aks/${APP}:${TAG}" "${IMG}"
make docker-push
