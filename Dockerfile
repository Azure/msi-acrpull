# Build the manager binary
FROM mcr.microsoft.com/azurelinux/base/core:3.0.20260909@sha256:34a22db497ff34a0f35ca5fc54bd38711d04238a2c1b2f65d35dc9d45dd82584 AS builder
ENV GOTOOLCHAIN=local \
    MS_GOTOOLCHAIN_TELEMETRY_ENABLED=0
RUN tdnf install -y ca-certificates curl git gzip tar \
    && tdnf clean all

ARG GO_VERSION=1.27.2-2
# Checksums from the Microsoft Go release, not the upstream Go distribution.
RUN case "$(uname -m)" in \
        x86_64) GO_ARCH=amd64; GO_SHA256SUM=37dc7dd8b0bbf881d80e25d7211319fe10b0bf86c29b321e9c7e3147110c5fc4 ;; \
        aarch64) GO_ARCH=arm64; GO_SHA256SUM=1e87af32aa7fe1b55d481f1d710b7f4ea7c5561d799c8f0c9634626e80edb002 ;; \
        *) echo "Unsupported Go build architecture: $(uname -m)" >&2; exit 1 ;; \
    esac \
    && GO_ARCHIVE="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" \
    && curl --retry 5 --retry-delay 10 --retry-all-errors -fSL "https://aka.ms/golang/release/latest/${GO_ARCHIVE}" -o /tmp/go.tar.gz \
    && echo "${GO_SHA256SUM}  /tmp/go.tar.gz" | sha256sum --check \
    && tar -C /usr/local -zxf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
RUN test "$(go env GOVERSION)" = "go1.27.2" \
    && test "$(cat /usr/local/go/MICROSOFT_REVISION)" = "2" \
    && GODEBUG=ms_version=1 go version

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

FROM mcr.microsoft.com/azurelinux/distroless/base:3.0@sha256:431ae1dc2924c41ae54c97c25676990f0c61d6295f42f5d07783c6976f58f1ef
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532
# These environment variable can be set at runtime to provide default values
ENV ACR_SERVER=""
ENV MANAGED_IDENTITY_RESOURCE_ID=""
ENV MANAGED_IDENTITY_CLIENT_ID=""
ENTRYPOINT ["/manager"]
