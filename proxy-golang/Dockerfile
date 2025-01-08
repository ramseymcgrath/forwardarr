# Stage 1: Build
FROM golang:1.20 as builder

WORKDIR /app

# Copy go.mod and go.sum first for caching
COPY ./proxy-golang/src/go.mod src/go.sum ./
RUN go mod download

# Copy the actual source
COPY ./proxy-golang/src/main.go ./main.go

# Build the binary
RUN CGO_ENABLED=0 go build -o proxyserver .
# Stage 2: Minimal runtime image
FROM alpine:3.18
RUN apk --no-cache add ca-certificates

# Create a non-root user (optional)
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

WORKDIR /app
COPY --from=builder /app/proxyserver /app/proxyserver

EXPOSE 8080

CMD ["/app/proxyserver"]
