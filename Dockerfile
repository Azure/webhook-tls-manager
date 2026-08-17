# Microsoft build of Go: routes Go crypto through the platform's FIPS-validated OpenSSL.
# Pinned to an exact patch tag so the compiler version is reproducible; bump deliberately.
FROM mcr.microsoft.com/oss/go/microsoft/golang:1.25.13-azurelinux3.0 AS build-stage

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
# Deliberately left on the rolling 3.0 tag: this is where OpenSSL ships, so it must pick up
# CVE fixes on rebuild. The build stage is pinned; the FIPS provider surface is not.
FROM mcr.microsoft.com/azurelinux/base/core:3.0
COPY --from=build-stage /app/webhook-tls-manager /

ENTRYPOINT ["/webhook-tls-manager"]
