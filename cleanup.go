package main

import (
	"os"
	"path/filepath"
	"time"
)

type Cleanup struct {
	directory string
	maxAge    time.Duration
	logger    *Logger
}

func NewCleanup(directory string, maxAge time.Duration, logger *Logger) *Cleanup {
	return &Cleanup{
		directory: directory,
		maxAge:    maxAge,
		logger:    logger,
	}
}

func (c *Cleanup) Start(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			c.cleanup()
		}
	}()
}

func (c *Cleanup) cleanup() {
	c.logger.Info("Starting cleanup of %s", c.directory)

	err := filepath.Walk(c.directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check if file is older than maxAge
		if time.Since(info.ModTime()) > c.maxAge {
			if err := os.Remove(path); err != nil {
				c.logger.Error("Failed to remove file %s: %v", path, err)
				return nil
			}
			c.logger.Info("Removed old file: %s", path)
		}

		return nil
	})

	if err != nil {
		c.logger.Error("Error during cleanup: %v", err)
	}
} 