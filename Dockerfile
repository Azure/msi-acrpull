# Build the manager binary
FROM mcr.microsoft.com/azurelinux/base/core:3.0@sha256:3d16d8799f71a78f5bddb3b7cda4a57df1f40ecfa58bac89933010596aa86880 AS builder
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

FROM mcr.microsoft.com/azurelinux/distroless/base:3.0@sha256:11ecd8f7cd1cad0e4fbb565ab98768f1a2ce35cb2730c867217baac011ae8645
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532
# These environment variable can be set at runtime to provide default values
ENV ACR_SERVER=""
ENV MANAGED_IDENTITY_RESOURCE_ID=""
ENV MANAGED_IDENTITY_CLIENT_ID=""
ENTRYPOINT ["/manager"]
