# Build stage  
FROM golang:1.25.1-alpine AS builder  

# Install git and certificates (needed for private repos and some dependencies)  
RUN apk add --no-cache git ca-certificates tzdata  

# Set working directory  
WORKDIR /app  

# Copy go mod and sum files  
COPY go.mod go.sum ./  

# Download dependencies  
RUN go mod download  

# Copy the source code  
COPY . .  

# Build the application  
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server cmd/main.go

# ------------------------------------------------------------------------

# Final stage  
FROM alpine:latest

# Import certificates from builder  
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/  

# Copy binary from builder  
COPY --from=builder /app/server /app/server  
COPY --from=builder /app/assets/google_confidential_space_root.crt /app/assets/google_confidential_space_root.crt

# Set environment variables  
ENV TZ=UTC

LABEL "tee.launch_policy.allow_env_override"="LOG_LEVEL"
LABEL "tee.launch_policy.allow_env_override"="PROXY_URL"
LABEL "tee.launch_policy.allow_env_override"="INITIAL_OWNER"
LABEL "tee.launch_policy.allow_env_override"="EXTENSION_ID"

# Expose port (adjust as needed)  
EXPOSE 5500

# Run the application
WORKDIR /app  
ENV MODE=0
CMD ["./server"]
