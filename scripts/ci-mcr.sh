#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

echo "docker login to ${REGISTRY}"
docker login ${REGISTRY} -u ${REGISTRY_USERNAME} -p ${REGISTRY_PASSWORD}

echo "docker login to ${MCR_REGISTRY}"
docker login ${MCR_REGISTRY} -u ${MCR_USERNAME} -p ${MCR_PASSWORD}

TAG=${BUILD_NUMBER}
echo "image tag will be ${TAG}"

IMG="${REGISTRY}/${APP}:${TAG}" make docker-build
docker tag "${REGISTRY}/${APP}:${TAG}" "${MCR_REGISTRY}${MCR_ORG}/${APP}:${TAG}"
docker push "${REGISTRY}/${APP}:${TAG}"
docker push "${MCR_REGISTRY}${MCR_ORG}/${APP}:${TAG}"

# push to latest tag as well
docker tag "${REGISTRY}/${APP}:${TAG}" "${MCR_REGISTRY}${MCR_ORG}/${APP}:latest"
docker push "${MCR_REGISTRY}${MCR_ORG}/${APP}:latest"
