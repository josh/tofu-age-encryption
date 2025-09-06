package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
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

type KeyProviderHeader struct {
	Magic   string `json:"magic"`
	Version int    `json:"version"`
}

type Metadata struct {
	ExternalData map[string]any `json:"external_data"`
}

type KeyProviderOutput struct {
	Keys struct {
		EncryptionKey []byte `json:"encryption_key,omitempty"`
		DecryptionKey []byte `json:"decryption_key,omitempty"`
	} `json:"keys"`
	Meta Metadata `json:"meta,omitempty"`
}

func main() {
	ctx := context.Background()

	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	encrypt := fs.Bool("encrypt", false, "encrypt payload")
	decrypt := fs.Bool("decrypt", false, "decrypt payload")
	keyProvider := fs.Bool("key-provider", false, "provide encryption keys")
	versionFlag := fs.Bool("version", false, "print version")
	ageRecipientFlag := fs.String("age-recipient", os.Getenv("AGE_RECIPIENT"), "age recipient")
	ageIdentityFileFlag := fs.String("age-identity-file", os.Getenv("AGE_IDENTITY_FILE"), "age identity file")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "usage: expected --encrypt or --decrypt\n")
		os.Exit(1)
	}

	if *versionFlag {
		fmt.Printf("tofu-age-encryption version %s\n", Version)
		return
	}

	log.Default().SetOutput(os.Stderr)
	log.Default().SetFlags(0) // suppress timestamps for deterministic output

	if (*encrypt && *decrypt) || (*encrypt && *keyProvider) || (*decrypt && *keyProvider) || (!*encrypt && !*decrypt && !*keyProvider) {
		fmt.Fprintf(os.Stderr, "usage: expected --encrypt or --decrypt or --key-provider\n")
		os.Exit(1)
	}

	ageProgram := AgeProgram
	if ageProgram == "" || ageProgram == "age" {
		if path, err := exec.LookPath("age"); err == nil {
			ageProgram = path
		}
	}

	if *keyProvider {
		handleKeyProvider(ctx, ageProgram, *ageRecipientFlag, *ageIdentityFileFlag)
		return
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

	ageIdentityFile := *ageIdentityFileFlag
	ageRecipient := *ageRecipientFlag

	var outputPayload []byte
	if *encrypt {
		outputPayload, err = ageEncryptPayload(ctx, ageProgram, ageRecipient, inputData.Payload)
		if err != nil {
			log.Fatalf("Failed to encrypt payload: %v", err)
		}
	}
	if *decrypt {
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

func handleKeyProvider(ctx context.Context, ageProgram, ageRecipient, ageIdentityFile string) {
	header := KeyProviderHeader{
		"OpenTofu-External-Key-Provider",
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
	var inMeta *Metadata
	if len(bytes.TrimSpace(input)) > 0 {
		if err := json.Unmarshal(input, &inMeta); err != nil {
			log.Fatalf("Failed to parse stdin: %v", err)
		}
	}

	var output KeyProviderOutput
	if inMeta == nil || len(inMeta.ExternalData) == 0 {
		if ageRecipient == "" {
			log.Fatalf("age recipient is required")
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			log.Fatalf("Failed to generate encryption key: %v", err)
		}
		encryptedKey, err := ageEncryptPayload(ctx, ageProgram, ageRecipient, key)
		if err != nil {
			log.Fatalf("Failed to encrypt key: %v", err)
		}
		output.Keys.EncryptionKey = key
		output.Meta = Metadata{ExternalData: map[string]any{
			"age_encrypted_key": base64.StdEncoding.EncodeToString(encryptedKey),
		}}
	} else {
		if ageIdentityFile == "" {
			log.Fatalf("age identity file is required")
		}
		encKeyStr, ok := inMeta.ExternalData["age_encrypted_key"].(string)
		if !ok {
			log.Fatalf("metadata missing age_encrypted_key")
		}
		encKey, err := base64.StdEncoding.DecodeString(encKeyStr)
		if err != nil {
			log.Fatalf("Failed to decode encrypted key: %v", err)
		}
		key, err := ageDecryptPayload(ctx, ageProgram, ageIdentityFile, encKey)
		if err != nil {
			log.Fatalf("Failed to decrypt key: %v", err)
		}
		output.Keys.EncryptionKey = key
		output.Keys.DecryptionKey = key
		output.Meta = *inMeta
	}

	outputData, err := json.Marshal(output)
	if err != nil {
		log.Fatalf("Failed to encode output: %v", err)
	}
	_, err = os.Stdout.Write(outputData)
	if err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}
}
