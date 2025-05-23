# Use the official Go image as base
FROM golang:1.24-alpine

# Install required system dependencies
RUN apk add --no-cache openssl bash git

# Install swag
RUN go install github.com/swaggo/swag/cmd/swag@latest

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code and scripts
COPY . .

# Create necessary directories
RUN mkdir -p /app/uploads /app/certs

# Generate SSL certificates
RUN chmod +x /app/generate_certs.sh && \
    cd /app && \
    ./generate_certs.sh

# Generate Swagger docs
RUN swag init

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# Expose the HTTPS port
EXPOSE 8443

# Create a non-root user
RUN adduser -D appuser && \
    chown -R appuser:appuser /app && \
    chmod -R 755 /app/certs

# Switch to non-root user
USER appuser

# Command to run the application
CMD ["./main"] 