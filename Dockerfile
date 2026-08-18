FROM golang:alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/main.go

# Start a new stage from scratch
FROM alpine:latest

WORKDIR /root/

# Install CA certificates, curl, and docker CLI
RUN apk --no-cache add ca-certificates curl docker-cli

# Install Docker Scout CLI plugin
RUN mkdir -p ~/.docker/cli-plugins && \
    curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh

COPY --from=builder /app/main .

# Script de arranque: hace docker login si se proveen credenciales, luego arranca el backend
RUN printf '#!/bin/sh\nif [ -n "$DOCKER_HUB_USER" ] && [ -n "$DOCKER_HUB_TOKEN" ]; then\n  echo "$DOCKER_HUB_TOKEN" | docker login -u "$DOCKER_HUB_USER" --password-stdin\nfi\nexec ./main\n' > /root/entrypoint.sh && chmod +x /root/entrypoint.sh

# Environment variables
ENV NEO4J_URI=neo4j://neo4j:7687
ENV NEO4J_USERNAME=neo4j
ENV NEO4J_PASSWORD=password
ENV PORT=8080
# Credenciales Docker Hub para Docker Scout (sobreescribir en docker-compose o --env)
ENV DOCKER_HUB_USER=""
ENV DOCKER_HUB_TOKEN=""

EXPOSE 8080

CMD ["/root/entrypoint.sh"]
