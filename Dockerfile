FROM golang:1.23.3 AS build-stage

WORKDIR /gomod
COPY go.mod go.sum ./

# Force using the installed Go version (1.23.3) instead of fetching 1.23.7
ENV GOTOOLCHAIN=local

RUN go mod download

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 go build -o webhook-tls-manager main.go

FROM scratch
COPY --from=build-stage /app/webhook-tls-manager /

ENTRYPOINT ["/webhook-tls-manager"]

