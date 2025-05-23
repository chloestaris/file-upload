#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Read credentials from .env file
if [ -f .env ]; then
    export $(cat .env | grep -v '#' | xargs)
else
    echo -e "${RED}Error: .env file not found${NC}"
    exit 1
fi

# Test endpoint
API_URL="https://localhost:8443"

echo -e "\n${GREEN}Testing File Upload API${NC}"
echo "================================"

# Test 1: Get JWT Token
echo -e "\n1. Getting JWT token..."
echo "Using credentials: ${API_USERNAME}:${API_PASSWORD}"
RESPONSE=$(curl -s -k \
    -X POST \
    -u "${API_USERNAME}:${API_PASSWORD}" \
    "${API_URL}/login")

TOKEN=$(echo "$RESPONSE" | sed 's/\\n//g' | grep -o '"token":[^}]*' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    echo -e "${RED}Failed to get JWT token${NC}"
    echo "Server response: $RESPONSE"
    exit 1
fi

echo -e "${GREEN}Successfully obtained JWT token${NC}"

# Test 2: Upload file with JWT
echo -e "\n2. Testing file upload with JWT..."
curl -X POST \
    -k \
    -H "Authorization: Bearer ${TOKEN}" \
    -F "file=@test.txt" \
    "${API_URL}/upload"

echo -e "\n\n${GREEN}Tests completed!${NC}" 