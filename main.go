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
	"unicode"
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
	inputFileFlag := fs.String("input-file", "", "read input from file instead of stdin")
	outputFileFlag := fs.String("output-file", "", "write output to file instead of stdout")
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

	// Configure input reader.
	in := io.Reader(os.Stdin)
	inputDesc := "stdin"
	if *inputFileFlag != "" {
		f, err := os.Open(*inputFileFlag)
		if err != nil {
			log.Fatalf("Failed to open input file: %v", err)
		}
		defer f.Close()
		in = f
		inputDesc = "input file"
	}

	// Configure output writer.
	out := io.Writer(os.Stdout)
	outputDesc := "stdout"
	if *outputFileFlag != "" {
		f, err := os.OpenFile(*outputFileFlag, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			log.Fatalf("Failed to open output file: %v", err)
		}
		defer f.Close()
		out = f
		outputDesc = "output file"
	}

	header := Header{
		"OpenTofu-External-Encryption-Method",
		1,
	}
	if err := json.NewEncoder(out).Encode(header); err != nil {
		log.Fatalf("Failed to write %s: %v", outputDesc, err)
	}

	dec := json.NewDecoder(in)
	var inputData Input
	var first json.RawMessage
	if err := dec.Decode(&first); err != nil {
		log.Fatalf("Failed to read %s: %v", inputDesc, err)
	}
	var hdr Header
	if err := json.Unmarshal(first, &hdr); err == nil && hdr.Magic == header.Magic {
		if err := dec.Decode(&first); err != nil {
			log.Fatalf("Failed to read %s: %v", inputDesc, err)
		}
	}
	if err := json.Unmarshal(first, &inputData); err != nil {
		log.Fatalf("Failed to parse %s: %v", inputDesc, err)
	}

	ageIdentityFile := *ageIdentityFileFlag
	if ageIdentityFile == "" {
		if env := os.Getenv("SOPS_AGE_KEY_FILE"); env != "" {
			ageIdentityFile = env
		} else if env := os.Getenv("SOPS_AGE_KEY"); env != "" {
			file, cleanup, err := writeTempIdentity(env)
			if err != nil {
				log.Fatalf("Failed to prepare identity: %v", err)
			}
			ageIdentityFile = file
			defer cleanup()
		} else {
			var cmdEnv, cmd string
			for _, name := range []string{"AGE_IDENTITY_COMMAND", "AGE_IDENTITY_CMD", "SOPS_AGE_KEY_CMD"} {
				if env := os.Getenv(name); env != "" {
					cmdEnv, cmd = name, env
					break
				}
			}
			if cmd != "" {
				key, err := runKeyCommand(ctx, cmd)
				if err != nil {
					log.Fatalf("Failed to execute %s: %v", cmdEnv, err)
				}
				file, cleanup, err := writeTempIdentity(key)
				if err != nil {
					log.Fatalf("Failed to prepare identity: %v", err)
				}
				ageIdentityFile = file
				defer cleanup()
			}
		}
	}

	var (
		outputPayload []byte
		err           error
	)
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
	if _, err = fmt.Fprintln(out, string(outputData)); err != nil {
		log.Fatalf("Failed to write %s: %v", outputDesc, err)
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
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
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
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
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
	parts, err := splitCommand(command)
	if err != nil {
		return "", fmt.Errorf("parse command: %w", err)
	}
	if len(parts) == 0 {
		return "", errors.New("empty command")
	}

	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	cmd.Stderr = os.Stderr

	output, err := cmd.Output()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
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

func splitCommand(s string) ([]string, error) {
	var (
		args    []string
		current strings.Builder
		inQuote rune
		escaped bool
	)
	for _, r := range s {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '\'' || r == '"':
			if inQuote == 0 {
				inQuote = r
			} else if inQuote == r {
				inQuote = 0
			} else {
				current.WriteRune(r)
			}
		case unicode.IsSpace(r) && inQuote == 0:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if escaped {
		return nil, errors.New("unterminated escape")
	}
	if inQuote != 0 {
		return nil, errors.New("unterminated quote")
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args, nil
}

func writeTempIdentity(key string) (string, func(), error) {
	f, err := os.CreateTemp("", "age-identity-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp identity file: %w", err)
	}
	if _, err := f.WriteString(key + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", nil, fmt.Errorf("write identity: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", nil, fmt.Errorf("close identity file: %w", err)
	}
	cleanup := func() { _ = os.Remove(f.Name()) }
	return f.Name(), cleanup, nil
}
