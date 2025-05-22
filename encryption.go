package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
)

// EncryptFile encrypts a file using AES-256-GCM
func EncryptFile(inputPath, outputPath string, key []byte) error {
	// Read the input file
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	// Create the cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Create nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Write the encrypted data
	return os.WriteFile(outputPath, ciphertext, 0644)
}

// DecryptFile decrypts a file using AES-256-GCM
func DecryptFile(inputPath, outputPath string, key []byte) error {
	// Read the encrypted file
	ciphertext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	// Create the cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Get the nonce size
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return err
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	// Write the decrypted data
	return os.WriteFile(outputPath, plaintext, 0644)
}

// GenerateEncryptionKey generates a random 32-byte key
func GenerateEncryptionKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
} 