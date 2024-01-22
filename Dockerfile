FROM golang:1.21 AS build-stage

WORKDIR /gomod
COPY go.mod go.sum ./
RUN go mod download

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 go build -o webhook-tls-manager main.go

FROM scratch
COPY --from=build-stage /app/webhook-tls-manager /

ENTRYPOINT ["/webhook-tls-manager"]


# RUN go build -o /webhook-tls-manager

# RUN chmod +x /webhook-tls-manager

# ENTRYPOINT ["/webhook-tls-manager"]

# FROM golang:1.21 AS build-stage

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

