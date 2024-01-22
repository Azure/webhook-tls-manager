COMMANDS=webhook-tls-manager

# PREFIX is base path to install.
PREFIX ?= /usr/local

GO_BUILDTAGS = -tags "osusergo netgo static_build"

# IMAGE_REPO is default repo for image-build recipe.
IMAGE_REPO ?= localhost:5000
IMAGE_TAG ?= latest
IMAGE_NAME = $(IMAGE_REPO)/webhook-tls-manager:$(IMAGE_TAG)

BINARIES=$(addprefix bin/,$(COMMANDS))

# default recipe is build
.DEFAULT_GOAL := build

# Always build
ALWAYS:

bin/%: cmd/% ALWAYS
	@CGO_ENABLED=0 go build -o $@ ${GO_BUILDTAGS} ./$<

build: $(BINARIES) ## build binaries
	@echo "$@"

install: ## install binaries
	@install -d $(PREFIX)/bin
	@install $(BINARIES) $(PREFIX)/bin

image-build: ## build image
	@echo building ${IMAGE_NAME}
	@docker build . -t ${IMAGE_NAME}

image-push: image-build ## push image
	@echo pushing ${IMAGE_NAME}
	@docker push ${IMAGE_NAME}

test: ## run test
	@go test -v ./...

lint: ## run lint
	@golangci-lint run --config .golangci.yml

.PHONY: clean
clean: ## clean up binaries
	@rm -f $(BINARIES)

.PHONY: help
help: ## this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-36s\033[0m%s\n", $$1, $$2}' $(MAKEFILE_LIST)