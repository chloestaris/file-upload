#!/bin/bash

# Create certs directory if it doesn't exist
mkdir -p certs

# Generate private key
openssl genrsa -out certs/server.key 2048

# Generate self-signed certificate
openssl req -new -x509 -sha256 -key certs/server.key -out certs/server.crt -days 365 \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Set permissions
chmod 400 certs/server.key
chmod 444 certs/server.crt

echo "Self-signed certificates generated in certs directory" 