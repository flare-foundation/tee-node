FROM golang:1.25.1-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server cmd/extension/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/extension cmd/extension_example/main.go

FROM alpine:latest

WORKDIR /app

RUN apk add gosu --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community

RUN adduser -DH -u 1000 server && adduser -DH -u 1001 extension

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/assets/google_confidential_space_root.crt assets/google_confidential_space_root.crt
COPY --from=builder /app/server /app/extension ./

ENV TZ=UTC  

LABEL "tee.launch_policy.allow_env_override"="LOG_LEVEL"

EXPOSE 5500

ENV MODE=0

CMD ["sh", "-c", "./server & gosu extension ./extension"]