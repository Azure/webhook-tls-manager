FROM golang:1.24.4 AS build-stage

# Copy dependencies
COPY go.mod go.sum ./
COPY vendor/ vendor/

# Set working directory
WORKDIR /app

# Force using the installed Go version (1.23.3) instead of fetching 1.23.7
ENV GOTOOLCHAIN=local

# Copy the entire source code
COPY . .

# Build the Go binary using vendored dependencies
RUN CGO_ENABLED=0 go build -mod=vendor -o webhook-tls-manager main.go

# Minimal final image (scratch for smallest size)
FROM scratch
COPY --from=build-stage /app/webhook-tls-manager /

ENTRYPOINT ["/webhook-tls-manager"]
