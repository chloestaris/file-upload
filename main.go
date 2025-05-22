package main

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

const (
	maxFileSize    = 10 << 20 // 10 MB
	uploadLimitMin = 10       // 10 uploads per minute
	maxFileAge     = 24 * time.Hour // Files older than 24 hours will be deleted
)

var (
	// Allowed file types
	allowedTypes = map[string]bool{
		"image/jpeg":      true,
		"image/png":       true,
		"image/gif":       true,
		"text/plain":      true,
		"application/pdf": true,
	}

	// Rate limiting
	uploadCount = make(map[string][]time.Time)
	uploadMutex = &sync.Mutex{}

	// Global logger
	logger *Logger

	// Encryption key
	encryptionKey []byte

	// Basic auth credentials (in production, use environment variables)
	apiUsername = "admin"
	apiPassword = "secure_password"
)

func init() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Initialize logger
	logger = NewLogger()

	// Initialize encryption key
	keyStr := os.Getenv("ENCRYPTION_KEY")
	if keyStr == "" {
		// Generate new key if not provided
		var err error
		keyStr, err = GenerateEncryptionKey()
		if err != nil {
			logger.Error("Failed to generate encryption key: %v", err)
			os.Exit(1)
		}
		logger.Info("Generated new encryption key: %s", keyStr)
	}

	var err error
	encryptionKey, err = hex.DecodeString(keyStr)
	if err != nil {
		logger.Error("Failed to decode encryption key: %v", err)
		os.Exit(1)
	}

	// Initialize cleanup routine
	cleanup := NewCleanup("uploads", maxFileAge, logger)
	cleanup.Start(1 * time.Hour) // Run cleanup every hour
}

// basicAuth middleware for authentication
func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Use constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(username), []byte(apiUsername)) != 1 ||
			subtle.ConstantTimeCompare([]byte(password), []byte(apiPassword)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// checkRateLimit verifies if the client hasn't exceeded the upload limit
func checkRateLimit(ip string) bool {
	uploadMutex.Lock()
	defer uploadMutex.Unlock()

	now := time.Now()
	timeWindow := now.Add(-time.Minute)

	// Remove old entries
	var recent []time.Time
	for _, t := range uploadCount[ip] {
		if t.After(timeWindow) {
			recent = append(recent, t)
		}
	}
	uploadCount[ip] = recent

	// Check rate limit
	if len(recent) >= uploadLimitMin {
		return false
	}

	// Add new upload time
	uploadCount[ip] = append(uploadCount[ip], now)
	return true
}

// sanitizeFilename removes potentially dangerous characters from filename
func sanitizeFilename(filename string) string {
	// Remove path components
	filename = filepath.Base(filename)
	
	// Remove special characters
	filename = strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-' || r == '_' || r == '.':
			return r
		default:
			return -1
		}
	}, filename)

	// Ensure filename isn't empty after sanitization
	if filename == "" {
		return "unnamed_file"
	}
	return filename
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	// Method validation
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get user from context
	username, ok := getUserFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Rate limiting
	clientIP := r.RemoteAddr
	if !checkRateLimit(clientIP) {
		http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
		return
	}

	// Parse the multipart form with size limit
	if err := r.ParseMultipartForm(maxFileSize); err != nil {
		http.Error(w, "File too large. Maximum size is 10MB", http.StatusBadRequest)
		return
	}

	// Get the file from the form data
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to get file from form", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate file size
	if header.Size > maxFileSize {
		http.Error(w, "File too large. Maximum size is 10MB", http.StatusBadRequest)
		return
	}

	// Validate file type
	contentType := header.Header.Get("Content-Type")
	if contentType == "" {
		// Try to detect content type
		buffer := make([]byte, 512)
		_, err := file.Read(buffer)
		if err != nil {
			http.Error(w, "Failed to detect file type", http.StatusBadRequest)
			return
		}
		contentType = http.DetectContentType(buffer)
		// Reset file pointer
		file.Seek(0, 0)
	}

	// Clean up content type
	contentType = strings.ToLower(strings.Split(contentType, ";")[0])
	if !allowedTypes[contentType] {
		http.Error(w, "File type not allowed", http.StatusBadRequest)
		return
	}

	// Ensure uploads directory exists
	if err := os.MkdirAll("uploads", 0755); err != nil {
		logger.Error("Failed to create uploads directory: %v", err)
		http.Error(w, "Failed to create uploads directory", http.StatusInternalServerError)
		return
	}

	// Sanitize filename and create unique name
	filename := sanitizeFilename(header.Filename)
	ext := filepath.Ext(filename)
	baseFilename := strings.TrimSuffix(filename, ext)
	timestamp := time.Now().Format("20060102150405")
	safeFilename := fmt.Sprintf("%s_%s_%s%s", username, baseFilename, timestamp, ext)
	
	// Create temporary file for initial upload
	tempPath := filepath.Join("uploads", "temp_"+safeFilename)
	dst, err := os.Create(tempPath)
	if err != nil {
		logger.Error("Failed to create temporary file: %v", err)
		http.Error(w, "Failed to create destination file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Copy the uploaded file to the temporary file
	if _, err := io.Copy(dst, file); err != nil {
		logger.Error("Failed to save file: %v", err)
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	// Close the file before encryption
	dst.Close()

	// Encrypt the file
	finalPath := filepath.Join("uploads", safeFilename)
	if err := EncryptFile(tempPath, finalPath, encryptionKey); err != nil {
		logger.Error("Failed to encrypt file: %v", err)
		http.Error(w, "Failed to process file", http.StatusInternalServerError)
		return
	}

	// Remove temporary file
	os.Remove(tempPath)

	// Log successful upload
	logger.Info("File uploaded successfully: %s by user %s", safeFilename, username)

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"message": "File uploaded successfully", "filename": "%s"}`, safeFilename)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// In production, validate against a database and use proper password hashing
	if username == os.Getenv("API_USERNAME") && password == os.Getenv("API_PASSWORD") {
		token, err := generateJWT(username)
		if err != nil {
			logger.Error("Failed to generate token: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token": "%s"}`, token)
		return
	}

	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

func main() {
	// Create TLS configuration
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}

	// Create server with timeouts
	server := &http.Server{
		Addr:         ":8443", // HTTPS port
		TLSConfig:    tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Register routes
	http.HandleFunc("/login", logger.LogRequest(loginHandler))
	http.HandleFunc("/upload", logger.LogRequest(jwtAuth(uploadHandler)))

	// Start HTTPS server
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	
	logger.Info("Server starting on port 8443 (HTTPS)...")
	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
		logger.Error("Server failed: %v", err)
		os.Exit(1)
	}
} 