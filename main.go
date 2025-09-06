package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
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
	ctx := context.Background()

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

	ageProgram := AgeProgram
	if ageProgram == "" || ageProgram == "age" {
		if path, err := exec.LookPath("age"); err == nil {
			ageProgram = path
		}
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

	// FIXME: Get age identity and recipient from env vars for now
	ageIdentityFile := os.Getenv("AGE_IDENTITY_FILE")
	ageRecipient := os.Getenv("AGE_RECIPIENT")

	var outputPayload []byte
	switch os.Args[1] {
	case "--encrypt":
		outputPayload, err = ageEncryptPayload(ctx, ageProgram, ageRecipient, inputData.Payload)
		if err != nil {
			log.Fatalf("Failed to encrypt payload: %v", err)
		}
	case "--decrypt":
		outputPayload, err = ageDecryptPayload(ctx, ageProgram, ageIdentityFile, inputData.Payload)
		if err != nil {
			log.Fatalf("Failed to decrypt payload: %v", err)
		}
	}

	output := Output{
		Payload: outputPayload,
	}
	outputData, err := json.Marshal(output)
	if err != nil {
		log.Fatalf("Failed to stringify output: %v", err)
	}
	_, err = os.Stdout.Write(append(outputData, []byte("\n")...))
	if err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}
}

func ageEncryptPayload(ctx context.Context, ageProgram string, pubkey string, payload []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, ageProgram, "--encrypt", "--recipient", pubkey)
	cmd.Stdin = bytes.NewReader(payload)

	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("timeout exceeded while encrypting payload with age")
		}

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("%s", string(exitErr.Stderr))
		}

		return nil, fmt.Errorf("failed to encrypt payload with age: %w", err)
	}

	return out, nil
}

func ageDecryptPayload(ctx context.Context, ageProgram string, identityFile string, payload []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, ageProgram, "--decrypt", "--identity", identityFile)
	cmd.Stdin = bytes.NewReader(payload)

	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("timeout exceeded while decrypting payload with age")
		}

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("%s", string(exitErr.Stderr))
		}

		return nil, fmt.Errorf("failed to decrypt payload with age: %w", err)
	}

	return out, nil
}
