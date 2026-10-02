ifndef TAG
	TAG := $(shell git rev-parse --short=7 HEAD)
endif

IMAGE_VERSION ?= $(TAG)

# Derived from the Dockerfile so the Go toolchain has a single source of truth. A stdlib CVE
# bump stays the two-file change it has always been: the Dockerfile FROM tag and go.mod.
GO_FIPS_IMAGE ?= $(shell awk '/^FROM .*\/golang:/ {print $$2; exit}' Dockerfile)

.PHONY: docker-build
docker-build:
	docker buildx build --platform linux/amd64,linux/arm64 --push -t $(REGISTRY):$(IMAGE_VERSION) .

# Exercises the crypto paths against the OpenSSL backend rather than Go's own crypto.
# The build-info assertion mirrors the Dockerfile guard: without it a silently disabled
# backend would still run the suite against Go's own crypto and pass CI green.
.PHONY: test-fips
test-fips:
	@test -n "$(GO_FIPS_IMAGE)" || { echo "could not parse the Go build image from Dockerfile"; exit 1; }
	docker run --rm -v "$(PWD)":/src -w /src -e GOTOOLCHAIN=local -e CGO_ENABLED=1 \
		-e GOEXPERIMENT=systemcrypto -e GOFLAGS=-mod=vendor $(GO_FIPS_IMAGE) \
		sh -c 'go build -o /tmp/fips-probe main.go && \
			go version -m /tmp/fips-probe | grep -q "microsoft_systemcrypto=1" && \
			go test ./...'
