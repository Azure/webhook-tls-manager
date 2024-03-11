ifndef TAG
	TAG := $(shell git rev-parse --short=7 HEAD)
endif

IMAGE_NAME ?= webhook-tls-manager
IMAGE_VERSION ?= $(TAG)

.PHONY: docker-build
docker-build:
	docker buildx build --platform linux/amd64 --push -t $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_VERSION) .