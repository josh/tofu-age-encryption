package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
)

// constants settable at build time.
var (
	AgeProgram = "age"
	Version    = "0.0.0"
)

type Header struct {
	Magic   string `json:"magic"`
	Version int    `json:"version"`
}

type Input struct {
	Key     []byte `json:"key,omitempty"`
	Payload []byte `json:"payload"`
}

type Output struct {
	Payload []byte `json:"payload"`
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version") {
		fmt.Printf("tofu-age-encryption version %s\n", Version)
		return
	}

	log.Default().SetOutput(os.Stderr)

	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: expected --encrypt or --decrypt\n")
		os.Exit(1)
	}
	if os.Args[1] != "--encrypt" && os.Args[1] != "--decrypt" {
		fmt.Fprintf(os.Stderr, "usage: expected --encrypt or --decrypt\n")
		os.Exit(1)
	}

	header := Header{
		"OpenTofu-External-Encryption-Method",
		1,
	}
	marshalledHeader, err := json.Marshal(header)
	if err != nil {
		log.Fatalf("%v", err)
	}
	_, err = os.Stdout.Write(append(marshalledHeader, []byte("\n")...))
	if err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("Failed to read stdin: %v", err)
	}
	var inputData Input
	if err = json.Unmarshal(input, &inputData); err != nil {
		log.Fatalf("Failed to parse stdin: %v", err)
	}

	var outputPayload []byte
	switch os.Args[1] {
	case "--encrypt":
		// TODO: encrypt the payload
	case "--decrypt":
		outputPayload = inputData.Payload
	}

	output := Output{
		Payload: outputPayload,
	}
	outputData, err := json.Marshal(output)
	if err != nil {
		log.Fatalf("Failed to stringify output: %v", err)
	}
	_, err = os.Stdout.Write(outputData)
	if err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}
}
