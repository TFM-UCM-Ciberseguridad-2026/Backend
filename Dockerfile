FROM golang:alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/main.go

# Start a new stage from scratch
FROM alpine:latest

WORKDIR /root/

# Install CA certificates to allow HTTPS requests (often needed for APIs)
RUN apk --no-cache add ca-certificates

COPY --from=builder /app/main .

# Environment variables
ENV NEO4J_URI=neo4j://neo4j:7687
ENV NEO4J_USERNAME=neo4j
ENV NEO4J_PASSWORD=password
ENV PORT=8080

EXPOSE 8080

CMD ["./main"]
