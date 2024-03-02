ifndef TAG
	TAG := $(shell git rev-parse --short=7 HEAD)
endif

IMAGE_NAME ?= webhook-tls-manager
IMAGE_VERSION ?= $(TAG)

.PHONY: docker-build
docker-build:
	docker build -t $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_VERSION) .