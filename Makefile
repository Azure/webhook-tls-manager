ifndef TAG
	TAG := $(shell git rev-parse --short=7 HEAD)
endif

IMAGE_VERSION ?= $(TAG)

.PHONY: docker-build
docker-build:
	docker buildx build --platform linux/amd64 -t $(REGISTRY):$(IMAGE_VERSION) .