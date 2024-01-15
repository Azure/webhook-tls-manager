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

CMD [ "/webhook-tls-manager" ]