# Stage 1: Build
FROM golang:1.25 as builder

WORKDIR /app

# Copy go.mod and go.sum first for caching
COPY ./proxy-golang/src/go.mod ./proxy-golang/src/go.sum ./
RUN go mod download

# Copy the actual source
COPY ./proxy-golang/src/main.go ./main.go

# Build the binary
RUN CGO_ENABLED=0 go build -o proxyserver .
# Stage 2: Minimal runtime image
FROM alpine:3.22
RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /app/proxyserver /app/proxyserver

EXPOSE 8080

ENV INDEXER_URLS_JSON=/config/indexer_urls.json
ENV API_KEYS_FILE=/config/api_keys.json
ENV PARAMETERS_CONFIG_FILE = /config/allowed_parameters.json
ENV DD_AGENT_HOST=localhost
ENV DD_DOGSTATSD_PORT=8125
ENV DD_IAST_ENABLED=true

CMD ["/app/proxyserver"]
