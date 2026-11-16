# Microsoft build of Go: routes Go crypto through the platform's FIPS-validated OpenSSL.
# Pinned to an exact patch tag so the compiler version is reproducible; bump deliberately.
FROM mcr.microsoft.com/oss/go/microsoft/golang:1.26.11-azurelinux3.0 AS build-stage

# Copy dependencies
COPY go.mod go.sum ./
COPY vendor/ vendor/

# Set working directory
WORKDIR /app

# Force using the Go version installed above instead of fetching the one in go.mod.
ENV GOTOOLCHAIN=local

# Default on Linux since Go 1.25; set explicitly for auditability. Go 1.27 rejects this value.
ENV GOEXPERIMENT=systemcrypto

# Copy the entire source code
COPY . .

# CGO is required by the OpenSSL crypto backend on Linux until Go 1.27.
RUN CGO_ENABLED=1 go build -mod=vendor -o webhook-tls-manager main.go

# Fail the build rather than silently shipping a binary that uses Go's own crypto.
RUN go version -m webhook-tls-manager | grep -q 'microsoft_systemcrypto=1'

# Azure Linux provides OpenSSL 3 plus the SymCrypt FIPS provider, which the binary dlopens at
# startup. A scratch image cannot satisfy this, and static linking to OpenSSL is not permitted.
# distroless/base keeps glibc, OpenSSL, SymCrypt and the CA bundle but drops curl, krb5, zlib,
# popt and tdnf, which the binary never uses and which carried most of the image CVEs.
# Pin the multi-architecture runtime base for reproducible builds.
# Update this digest deliberately to pick up future runtime package security fixes.
FROM mcr.microsoft.com/azurelinux/distroless/base:3.0@sha256:370fb2c55e7f0474fed019623cce6a8db65a4d70dedfca9219fc69d6c7627f89
COPY --from=build-stage /app/webhook-tls-manager /

ENTRYPOINT ["/webhook-tls-manager"]
