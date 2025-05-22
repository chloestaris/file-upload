# Secure File Upload API

A highly secure REST API built with Go that handles file uploads with multiple security features and best practices.

## Security Features

1. **Authentication & Authorization**
   - JWT-based authentication
   - Secure token generation and validation
   - Role-based access control

2. **File Security**
   - AES-256-GCM encryption for stored files
   - File type validation
   - Secure filename handling
   - Automatic file cleanup

3. **Transport Security**
   - HTTPS/TLS 1.2+
   - Strong cipher suites
   - Perfect forward secrecy

4. **Rate Limiting**
   - Per-IP rate limiting
   - Configurable limits
   - Thread-safe implementation

5. **Logging & Monitoring**
   - Detailed request logging
   - Error tracking
   - Performance monitoring

6. **Additional Security Measures**
   - Secure headers
   - Request timeouts
   - Input validation
   - Path traversal prevention

## Prerequisites

- Go 1.21 or higher
- OpenSSL (for generating certificates)
- Environment variables setup

## Getting Started

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd file-upload
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

3. Generate self-signed certificates (for development):
   ```bash
   ./generate_certs.sh
   ```

4. Create a `.env` file:
   ```env
   API_USERNAME=admin
   API_PASSWORD=secure_password
   JWT_SECRET=your-super-secret-key-change-this-in-production
   ENCRYPTION_KEY=32-char-key-here-change-in-production
   TLS_CERT_FILE=./certs/server.crt
   TLS_KEY_FILE=./certs/server.key
   ```

5. Run the server:
   ```bash
   go run *.go
   ```

The server will start on port 8443 (HTTPS).

## API Endpoints

### 1. Login

**Endpoint:** `POST /login`

**Authentication:**
- Basic Authentication
- Username and password from environment variables

**Response:**
```json
{
  "token": "your.jwt.token"
}
```

### 2. Upload File

**Endpoint:** `POST /upload`

**Authentication:**
- Bearer token (JWT)
- Include in Authorization header: `Bearer <token>`

**Request:**
- Method: POST
- Content-Type: multipart/form-data
- Form field name: `file`
- Maximum file size: 10MB
- Allowed file types: JPEG, PNG, GIF, TXT, PDF

**Response:**
- Success (200 OK):
  ```json
  {
    "message": "File uploaded successfully",
    "filename": "username_example_20230615123456.txt"
  }
  ```
- Error Responses:
  - 400 Bad Request: Invalid file type or size
  - 401 Unauthorized: Invalid or missing token
  - 429 Too Many Requests: Rate limit exceeded
  - 500 Internal Server Error: Server-side error

## Example Usage

1. Get JWT token:
```bash
curl -X POST -u admin:secure_password https://localhost:8443/login -k
```

2. Upload file using token:
```bash
curl -X POST \
  -H "Authorization: Bearer <your-token>" \
  -F "file=@/path/to/your/file.txt" \
  https://localhost:8443/upload -k
```

Using Postman:
1. Login:
   - Create POST request to `https://localhost:8443/login`
   - Add Basic Auth credentials
   - Send request to get JWT token

2. Upload:
   - Create POST request to `https://localhost:8443/upload`
   - Add Bearer Token from login response
   - Add file in form-data
   - Send request

## Security Notes

1. **Production Deployment**
   - Use proper SSL certificates
   - Change all default credentials
   - Use secure key storage (e.g., HashiCorp Vault)
   - Enable proper firewall rules

2. **File Storage**
   - Monitor disk usage
   - Implement backup strategies
   - Consider using object storage (e.g., S3)

3. **Monitoring**
   - Set up alerts for failed uploads
   - Monitor rate limit hits
   - Track file encryption errors

4. **Maintenance**
   - Regularly rotate encryption keys
   - Update dependencies
   - Review logs for suspicious activity

## File Lifecycle

1. **Upload**
   - File received and validated
   - Type and size checks
   - Sanitized filename generated

2. **Processing**
   - Temporary file created
   - File encrypted
   - Moved to final location

3. **Cleanup**
   - Files older than 24 hours automatically removed
   - Temporary files cleaned up
   - Failed uploads deleted

## Error Handling

The API provides detailed error messages while avoiding exposure of sensitive information:

- File validation errors
- Authentication failures
- Rate limit notifications
- Server-side processing errors

## Contributing

1. Follow security best practices
2. Add tests for new features
3. Update documentation
4. Use secure coding guidelines # file-upload
