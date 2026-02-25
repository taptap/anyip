FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /anyip ./src

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /anyip /usr/local/bin/anyip
EXPOSE 53/udp 53/tcp 443/tcp
ENTRYPOINT ["anyip"]
