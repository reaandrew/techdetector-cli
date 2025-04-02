package main

import (
	log "github.com/sirupsen/logrus"
	"os"
)

var Version string

func setupLogging() {
	// Create or open the error log file
	logFile, err := os.OpenFile("techdetector-cli.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Println("Failed to open error log file:", err)
		return
	}

	// Set Logrus output to both stdout and the error log file
	log.SetOutput(logFile)

	// Set log level to capture errors and above (i.e., error, fatal, panic)
	log.SetLevel(log.InfoLevel)

	// Format log output (optional)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
}

func main() {
	setupLogging()

	cli := &Cli{}
	if err := cli.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
}
