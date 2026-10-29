# Build the manager binary
FROM mcr.microsoft.com/azurelinux/base/core:3.0@sha256:88fc2b4a425801b3b4d8fe5342e24fb6134669fb718ec970340bdd36dee50c35 AS builder
ENV GOTOOLCHAIN=local \
    MS_GOTOOLCHAIN_TELEMETRY_ENABLED=0
RUN tdnf install -y ca-certificates git golang \
    && tdnf clean all

ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY ./ ./

# Build
# the GOARCH has not a default value to allow the binary be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager -tags=requirefips cmd/main.go

FROM mcr.microsoft.com/azurelinux/distroless/base:3.0@sha256:e952865122598043cfb54f0257f016e28e02c21904e172b47dcb2148e095693a
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532
# These environment variable can be set at runtime to provide default values
ENV ACR_SERVER=""
ENV MANAGED_IDENTITY_RESOURCE_ID=""
ENV MANAGED_IDENTITY_CLIENT_ID=""
ENTRYPOINT ["/manager"]
