FROM golang:1.22 AS build-stage

WORKDIR /gomod
COPY go.mod go.sum ./
RUN go mod download

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 go build -o webhook-tls-manager main.go

FROM scratch
COPY --from=build-stage /app/webhook-tls-manager /

ENTRYPOINT ["/webhook-tls-manager"]

