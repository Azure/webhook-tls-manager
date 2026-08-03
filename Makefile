ifndef TAG
	TAG := $(shell git rev-parse --short=7 HEAD)
endif

IMAGE_VERSION ?= $(TAG)

GO_FIPS_IMAGE ?= mcr.microsoft.com/oss/go/microsoft/golang:1.25-azurelinux3.0

.PHONY: docker-build
docker-build:
	docker buildx build --platform linux/amd64,linux/arm64 --push -t $(REGISTRY):$(IMAGE_VERSION) .

# Exercises the crypto paths against the OpenSSL backend rather than Go's own crypto.
.PHONY: test-fips
test-fips:
	docker run --rm -v "$(PWD)":/src -w /src -e GOTOOLCHAIN=local -e CGO_ENABLED=1 \
		-e GOEXPERIMENT=systemcrypto -e GOFLAGS=-mod=vendor $(GO_FIPS_IMAGE) \
		go test ./...