package main

import (
	"bufio"
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
	"runtime"
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
type mode int

const (
	modeEncrypt mode = iota
	modeDecrypt
)

type Config struct {
	mode            mode
	ageRecipients   []string
	ageIdentityFile string
	ageIdentity     string
	ageProgram      string
	inputFile       string
	outputFile      string
	version         bool
}

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

func parseConfig(ctx context.Context, args []string) (Config, error) {
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
	ageIdentityFlag := fs.String("age-identity", "", "age identity string")
	ageIdentityCommandFlag := fs.String("age-identity-command", "", "command whose output is the age identity")
	ageProgramFlag := fs.String("age-path", ageProgram, "path to age binary")
	inputFileFlag := fs.String("input-file", "", "read input from file instead of stdin")
	outputFileFlag := fs.String("output-file", "", "write output to file instead of stdout")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			orig := fs.Output()
			fs.SetOutput(os.Stdout)
			fs.Usage()
			fs.SetOutput(orig)
			return Config{}, flag.ErrHelp
		}
		return Config{}, err
	}

	var recipients []string
	recipients = append(recipients, ageRecipients...)

	for _, envVar := range []string{"AGE_RECIPIENT", "SOPS_AGE_RECIPIENTS"} {
		if val := os.Getenv(envVar); val != "" {
			var tmp sliceFlag
			_ = tmp.Set(val)
			recipients = append(recipients, tmp...)
		}
	}

	if *ageRecipientsFileFlag != "" {
		rs, err := parseRecipientsFile(*ageRecipientsFileFlag)
		if err != nil {
			return Config{}, fmt.Errorf("read age recipients file: %w", err)
		}
		recipients = append(recipients, rs...)
	}

	// Deduplicate recipients.
	seen := make(map[string]struct{})
	deduped := make([]string, 0, len(recipients))
	for _, r := range recipients {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		deduped = append(deduped, r)
	}

	cfg := Config{
		ageRecipients: deduped,
		ageProgram:    *ageProgramFlag,
		inputFile:     *inputFileFlag,
		outputFile:    *outputFileFlag,
		version:       *versionFlag,
	}

	if cfg.version {
		return cfg, nil
	}

	if (*encrypt && *decrypt) || (!*encrypt && !*decrypt) {
		return Config{}, fmt.Errorf("expected --encrypt or --decrypt")
	}
	if *encrypt {
		cfg.mode = modeEncrypt
	} else {
		cfg.mode = modeDecrypt
	}

	ageIdentityFile := *ageIdentityFileFlag
	var ageIdentity string
	if ageIdentityFile == "" {
		switch {
		case *ageIdentityFlag != "":
			ageIdentity = *ageIdentityFlag
		case *ageIdentityCommandFlag != "":
			key, err := runKeyCommand(ctx, *ageIdentityCommandFlag)
			if err != nil {
				return Config{}, fmt.Errorf("failed to execute age identity command: %w", err)
			}
			ageIdentity = key
		case os.Getenv("SOPS_AGE_KEY_FILE") != "":
			ageIdentityFile = os.Getenv("SOPS_AGE_KEY_FILE")
		case os.Getenv("SOPS_AGE_KEY") != "":
			ageIdentity = os.Getenv("SOPS_AGE_KEY")
		default:
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
					return Config{}, fmt.Errorf("failed to execute %s: %w", cmdEnv, err)
				}
				ageIdentity = key
			}
		}
	}
	cfg.ageIdentityFile = ageIdentityFile
	cfg.ageIdentity = ageIdentity

	return cfg, nil
}

func main() {
	ctx := context.Background()

	cfg, err := parseConfig(ctx, os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "usage: expected --encrypt or --decrypt\n")
		os.Exit(1)
	}

	if cfg.version {
		fmt.Printf("tofu-age-encryption version %s\n", Version)
		return
	}

	log.Default().SetOutput(os.Stderr)
	log.Default().SetFlags(0) // suppress timestamps for deterministic output

	// Configure input reader.
	in := io.Reader(os.Stdin)
	inputDesc := "stdin"
	if cfg.inputFile != "" {
		f, err := os.Open(cfg.inputFile)
		if err != nil {
			log.Fatalf("Failed to open input file: %v", err)
		}
		defer func() {
			_ = f.Close()
		}()
		in = f
		inputDesc = "input file"
	}

	// Configure output writer.
	out := io.Writer(os.Stdout)
	outputDesc := "stdout"
	if cfg.outputFile != "" {
		f, err := os.OpenFile(cfg.outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			log.Fatalf("Failed to open output file: %v", err)
		}
		defer func() {
			_ = f.Close()
		}()
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

	var (
		outputPayload []byte
		opErr         error
	)
	if cfg.mode == modeEncrypt {
		outputPayload, opErr = ageEncryptPayload(ctx, &cfg, inputData.Payload)
		if opErr != nil {
			log.Fatalf("Failed to encrypt payload: %v", opErr)
		}
	}
	if cfg.mode == modeDecrypt {
		outputPayload, opErr = ageDecryptPayload(ctx, &cfg, inputData.Payload)
		if opErr != nil {
			log.Fatalf("Failed to decrypt payload: %v", opErr)
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

func ageEncryptPayload(ctx context.Context, cfg *Config, payload []byte) ([]byte, error) {
	if len(cfg.ageRecipients) == 0 {
		return nil, errors.New("no recipients specified")
	}
	if _, err := exec.LookPath(cfg.ageProgram); err != nil {
		return nil, fmt.Errorf("age program not found: %s", cfg.ageProgram)
	}
	recipientsFile, cleanup, err := writeTempRecipients(cfg.ageRecipients)
	if err != nil {
		return nil, fmt.Errorf("write recipients to temp file: %w", err)
	}
	defer cleanup()

	args := []string{"--encrypt", "--recipients-file", recipientsFile}
	cmd := exec.CommandContext(ctx, cfg.ageProgram, args...)
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

func ageDecryptPayload(ctx context.Context, cfg *Config, payload []byte) ([]byte, error) {
	if cfg.ageIdentityFile == "" && cfg.ageIdentity == "" {
		return nil, errors.New("no identity specified")
	}
	if _, err := exec.LookPath(cfg.ageProgram); err != nil {
		return nil, fmt.Errorf("age program not found: %s", cfg.ageProgram)
	}
	args := []string{"--decrypt"}
	var (
		extra   []*os.File
		cleanup func()
	)
	if cfg.ageIdentityFile != "" {
		args = append(args, "--identity", cfg.ageIdentityFile)
	} else if cfg.ageIdentity != "" {
		if runtime.GOOS == "windows" {
			var err error
			cfg.ageIdentityFile, cleanup, err = writeTempIdentity(cfg.ageIdentity)
			if err != nil {
				return nil, fmt.Errorf("write identity to temp file: %w", err)
			}
			fmt.Fprintln(os.Stderr, "warning: writing age identity to a temporary file on Windows")
			args = append(args, "--identity", cfg.ageIdentityFile)
			defer cleanup()
		} else {
			r, w, err := os.Pipe()
			if err != nil {
				return nil, fmt.Errorf("pipe identity: %w", err)
			}
			if _, err := io.WriteString(w, cfg.ageIdentity+"\n"); err != nil {
				_ = w.Close()
				_ = r.Close()
				return nil, fmt.Errorf("write identity: %w", err)
			}
			if err := w.Close(); err != nil {
				_ = r.Close()
				return nil, fmt.Errorf("write identity: %w", err)
			}
			extra = append(extra, r)
			fd := 3 + len(extra) - 1
			args = append(args, "--identity", fmt.Sprintf("/dev/fd/%d", fd)) // works on Linux and macOS
			defer func() {
				_ = r.Close()
			}()
		}
	}

	cmd := exec.CommandContext(ctx, cfg.ageProgram, args...)
	if len(extra) > 0 {
		cmd.ExtraFiles = append(cmd.ExtraFiles, extra...)
	}
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

func parseRecipientsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var recipients []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		recipients = append(recipients, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return recipients, nil
}

func runKeyCommand(ctx context.Context, command string) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
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

func writeTempLines(lines []string, pattern string) (string, func(), error) {
	tmpfile, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	for _, line := range lines {
		if _, err := tmpfile.WriteString(line + "\n"); err != nil {
			_ = tmpfile.Close()
			_ = os.Remove(tmpfile.Name())
			return "", nil, fmt.Errorf("failed to write temp file: %w", err)
		}
	}

	if err := tmpfile.Close(); err != nil {
		_ = os.Remove(tmpfile.Name())
		return "", nil, fmt.Errorf("failed to close temp file: %w", err)
	}

	cleanup := func() {
		_ = os.Remove(tmpfile.Name())
	}

	return tmpfile.Name(), cleanup, nil
}

func writeTempIdentity(identity string) (string, func(), error) {
	return writeTempLines([]string{identity}, "age-identity-*")
}

func writeTempRecipients(recipients []string) (string, func(), error) {
	return writeTempLines(recipients, "age-recipients-*")
}
