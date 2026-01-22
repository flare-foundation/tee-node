# Build stage
FROM docker.io/golang:1.25.1-alpine@sha256:ac09a5f469f307e5da71e766b0bd59c9c49ea460a528cc3e6686513d64a6f1fb AS builder

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH

# Install git and certificates (needed for private repos and some dependencies)
RUN apk add --no-cache \
    git=2.52.0-r0 \
    ca-certificates=20251003-r0 \
    tzdata=2025c-r0

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Verify hashes
RUN go mod verify

# Copy the source code
COPY assets/ assets/
COPY cmd/ cmd/
COPY internal/ internal/
COPY pkg/ pkg/

# Build the application with reproducible flags
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-buildid=" -o /app/server cmd/main.go

# Set file modification times to SOURCE_DATE_EPOCH for reproducibility
RUN find /app -exec touch -d "@${SOURCE_DATE_EPOCH}" {} +

# ------------------------------------------------------------------------

# Final stage
FROM docker.io/alpine:latest@sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH

# Import certificates from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary from builder
COPY --from=builder /app/server /app/server
COPY --from=builder /app/assets/google_confidential_space_root.crt /app/assets/google_confidential_space_root.crt

# Set file modification times to SOURCE_DATE_EPOCH for reproducibility
RUN find /app /etc/ssl/certs -exec touch -d "@${SOURCE_DATE_EPOCH}" {} + 2>/dev/null || true

# Set environment variables
ENV TZ=UTC

LABEL "tee.launch_policy.allow_env_override"="LOG_LEVEL,PROXY_URL,INITIAL_OWNER,EXTENSION_ID"

# Expose port (adjust as needed)
EXPOSE 5500

# Run the application
WORKDIR /app
ENV MODE=0
CMD ["./server"]
