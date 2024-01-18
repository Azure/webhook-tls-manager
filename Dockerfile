# syntax=docker/dockerfile:1

FROM golang:1.21

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .

RUN go build -o /webhook-tls-manager

# Set execute permission on the binary
RUN chmod +x /webhook-tls-manager

# FROM golang:1.20 AS build-stage

# WORKDIR /gomod
# COPY go.mod go.sum ./
# RUN go mod download

# RUN mkdir -p /output

# WORKDIR /webhook-tls-manager-build
# RUN --mount=source=./,target=/webhook-tls-manager-build,rw make build && PREFIX=/output make install

# FROM gcr.io/distroless/static-debian12:nonroot AS release-stage

# WORKDIR /

# COPY --from=build-stage /output/bin/webhook-tls-manager /webhook-tls-manager

# USER nonroot:nonroot

ENTRYPOINT ["/webhook-tls-manager"]