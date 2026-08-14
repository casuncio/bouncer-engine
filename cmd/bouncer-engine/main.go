package main

import (
	"fmt"
	"log/slog"
	"os"
)

func main() {
	// Initialize a basic structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	slog.Info("Starting bouncer-engine", "version", "0.0.1", "status", "initializing")
	
	fmt.Println("Bouncer Engine is ready to go.")
}