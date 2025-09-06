package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
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

type sliceFlag []string

func (s *sliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *sliceFlag) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

func main() {
	ctx := context.Background()

	ageProgram := AgeProgram
	if ageProgram == "" || ageProgram == "age" {
		if path, err := exec.LookPath("age"); err == nil {
			ageProgram = path
		}
	}

	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {
		msg := fmt.Sprintf("Usage: %s [--encrypt | --decrypt] [options]\n", os.Args[0])
		if _, err := fmt.Fprint(fs.Output(), msg); err != nil {
			if _, err = fmt.Fprint(os.Stderr, msg); err != nil {
				panic(err)
			}
		}
		fs.PrintDefaults()
	}
	encrypt := fs.Bool("encrypt", false, "encrypt payload")
	decrypt := fs.Bool("decrypt", false, "decrypt payload")
	versionFlag := fs.Bool("version", false, "print version")
	var ageRecipients sliceFlag
	fs.Var(&ageRecipients, "age-recipient", "age recipient")
	ageRecipientsFileFlag := fs.String("age-recipients-file", os.Getenv("AGE_RECIPIENTS_FILE"), "age recipients file")
	ageIdentityFileFlag := fs.String("age-identity-file", os.Getenv("AGE_IDENTITY_FILE"), "age identity file")
	ageProgramFlag := fs.String("age-path", ageProgram, "path to age binary")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			orig := fs.Output()
			fs.SetOutput(os.Stdout)
			fs.Usage()
			fs.SetOutput(orig)
			return
		}
		fmt.Fprintf(os.Stderr, "usage: expected --encrypt or --decrypt\n")
		os.Exit(1)
	}

	if len(ageRecipients) == 0 {
		if env := os.Getenv("AGE_RECIPIENT"); env != "" {
			// Fall back to comma-separated AGE_RECIPIENT when no flags are provided.
			_ = ageRecipients.Set(env)
		} else if env := os.Getenv("SOPS_AGE_RECIPIENTS"); env != "" {
			_ = ageRecipients.Set(env)
		}
	}

	if *versionFlag {
		fmt.Printf("tofu-age-encryption version %s\n", Version)
		return
	}

	log.Default().SetOutput(os.Stderr)
	log.Default().SetFlags(0) // suppress timestamps for deterministic output

	if (*encrypt && *decrypt) || (!*encrypt && !*decrypt) {
		fmt.Fprintf(os.Stderr, "usage: expected --encrypt or --decrypt\n")
		os.Exit(1)
	}

	ageProgram = *ageProgramFlag

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
	if ageIdentityFile == "" {
		if env := os.Getenv("SOPS_AGE_KEY_FILE"); env != "" {
			ageIdentityFile = env
		} else if env := os.Getenv("SOPS_AGE_KEY"); env != "" {
			f, err := os.CreateTemp("", "age-identity-*")
			if err != nil {
				log.Fatalf("Failed to create temp identity file: %v", err)
			}
			if _, err := f.WriteString(env + "\n"); err != nil {
				_ = f.Close()
				log.Fatalf("Failed to write identity: %v", err)
			}
			if err := f.Close(); err != nil {
				log.Fatalf("Failed to close identity file: %v", err)
			}
			ageIdentityFile = f.Name()
			defer os.Remove(f.Name())
		} else if env := os.Getenv("SOPS_AGE_KEY_CMD"); env != "" {
			key, err := runKeyCommand(ctx, env)
			if err != nil {
				log.Fatalf("Failed to execute SOPS_AGE_KEY_CMD: %v", err)
			}
			f, err := os.CreateTemp("", "age-identity-*")
			if err != nil {
				log.Fatalf("Failed to create temp identity file: %v", err)
			}
			if _, err := f.WriteString(key + "\n"); err != nil {
				_ = f.Close()
				log.Fatalf("Failed to write identity: %v", err)
			}
			if err := f.Close(); err != nil {
				log.Fatalf("Failed to close identity file: %v", err)
			}
			ageIdentityFile = f.Name()
			defer os.Remove(f.Name())
		}
	}

	var outputPayload []byte
	if *encrypt {
		outputPayload, err = ageEncryptPayload(ctx, ageProgram, []string(ageRecipients), *ageRecipientsFileFlag, inputData.Payload)
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

func ageEncryptPayload(ctx context.Context, ageProgram string, pubkeys []string, recipientsFile string, payload []byte) ([]byte, error) {
	args := []string{"--encrypt"}
	if recipientsFile != "" {
		args = append(args, "--recipients-file", recipientsFile)
	}
	for _, r := range pubkeys {
		args = append(args, "--recipient", r)
	}
	cmd := exec.CommandContext(ctx, ageProgram, args...)
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

func runKeyCommand(ctx context.Context, command string) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Stderr = os.Stderr

	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("timeout exceeded while executing command")
		}
		return "", fmt.Errorf("failed to execute command: %w", err)
	}

	key := strings.TrimSpace(string(output))
	if key == "" {
		return "", errors.New("empty command output")
	}
	return key, nil
}
