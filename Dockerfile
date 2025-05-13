# Build the manager binary
FROM mcr.microsoft.com/oss/go/microsoft/golang:1.23-fips-azurelinux3.0 as builder
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
RUN GOEXPERIMENT=systemcrypto GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager -tags=requirefips cmd/main.go

FROM mcr.microsoft.com/azurelinux/base/core:3.0
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532
# These environment variable can be set at runtime to provide default values
ENV ACR_SERVER=""
ENV MANAGED_IDENTITY_RESOURCE_ID=""
ENV MANAGED_IDENTITY_CLIENT_ID=""
ENTRYPOINT ["/manager"]
