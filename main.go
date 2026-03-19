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
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// constants settable at build time.
var (
	Version       = "1.0.0"
	AgePluginPath = ""
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

type mode int

const (
	modeEncrypt mode = iota
	modeDecrypt
)

type Config struct {
	mode          mode
	ageRecipients map[string]bool
	ageIdentity   string
	agePluginPath string
	version       bool
}

func parseRecipients(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseConfig(ctx context.Context, args []string) (Config, error) {
	if len(args) > 0 {
		switch args[0] {
		case "encrypt", "decrypt", "version":
			args[0] = "--" + args[0]
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
	recipients := make(map[string]bool)
	fs.Func("recipient", "age recipient", func(value string) error {
		for _, r := range parseRecipients(value) {
			recipients[r] = true
		}
		return nil
	})
	var recipientsFiles []string
	fs.Func("recipients-file", "age recipients file", func(value string) error {
		recipientsFiles = append(recipientsFiles, value)
		return nil
	})
	identityFileFlag := fs.String("identity-file", os.Getenv("AGE_IDENTITY_FILE"), "age identity file")
	identityFlag := fs.String("identity", os.Getenv("AGE_IDENTITY"), "age identity string, file:PATH or cmd:COMMAND")
	identityCommandFlag := fs.String("identity-command", "", "command whose output is the age identity")
	agePluginPathFlag := fs.String("age-plugin-path", "", "colon-separated paths to search for age plugins")
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

	for _, envVar := range []string{"AGE_RECIPIENT", "AGE_RECIPIENTS", "SOPS_AGE_RECIPIENTS"} {
		if val := os.Getenv(envVar); val != "" {
			for _, r := range parseRecipients(val) {
				recipients[r] = true
			}
		}
	}

	if len(recipientsFiles) == 0 {
		if env := os.Getenv("AGE_RECIPIENTS_FILE"); env != "" {
			recipientsFiles = append(recipientsFiles, env)
		}
	}
	for _, recipientsFile := range recipientsFiles {
		rs, err := parseRecipientsFile(recipientsFile)
		if err != nil {
			return Config{}, fmt.Errorf("read age recipients file: %w", err)
		}
		for _, r := range rs {
			recipients[r] = true
		}
	}

	cfg := Config{
		ageRecipients: recipients,
		agePluginPath: *agePluginPathFlag,
		version:       *versionFlag,
	}

	if cfg.version {
		return cfg, nil
	}

	if (*encrypt && *decrypt) || (!*encrypt && !*decrypt) {
		return Config{}, fmt.Errorf("usage: expected --encrypt or --decrypt")
	}
	if *encrypt {
		cfg.mode = modeEncrypt
	} else {
		cfg.mode = modeDecrypt
	}

	if cfg.mode == modeDecrypt {
		var ageIdentity string
		ageIdentityFile := *identityFileFlag
		if ageIdentityFile == "" {
			switch {
			case *identityFlag != "":
				val := *identityFlag
				switch {
				case strings.HasPrefix(val, "file:"):
					ageIdentityFile = strings.TrimPrefix(val, "file:")
				case strings.HasPrefix(val, "cmd:"):
					key, err := runKeyCommand(ctx, strings.TrimPrefix(val, "cmd:"))
					if err != nil {
						return Config{}, fmt.Errorf("failed to execute age identity command: %w", err)
					}
					ageIdentity = key
				case strings.HasPrefix(val, "command:"):
					key, err := runKeyCommand(ctx, strings.TrimPrefix(val, "command:"))
					if err != nil {
						return Config{}, fmt.Errorf("failed to execute age identity command: %w", err)
					}
					ageIdentity = key
				default:
					ageIdentity = val
				}
			case *identityCommandFlag != "":
				key, err := runKeyCommand(ctx, *identityCommandFlag)
				if err != nil {
					return Config{}, fmt.Errorf("failed to execute age identity command: %w", err)
				}
				ageIdentity = key
			case os.Getenv("AGE_KEY_FILE") != "":
				ageIdentityFile = os.Getenv("AGE_KEY_FILE")
			case os.Getenv("AGE_KEY") != "":
				ageIdentity = os.Getenv("AGE_KEY")
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
		if ageIdentityFile != "" {
			content, err := os.ReadFile(ageIdentityFile)
			if err != nil {
				return Config{}, fmt.Errorf("failed to read identity file %q: %w", ageIdentityFile, err)
			}
			ageIdentity = string(content)
		}
		cfg.ageIdentity = ageIdentity
	}

	return cfg, nil
}

func main() {
	ctx := context.Background()

	cfg, err := parseConfig(ctx, os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	if cfg.version {
		fmt.Printf("tofu-age-encryption version %s\n", Version)
		return
	}

	var pluginPaths []string
	if cfg.agePluginPath != "" {
		pluginPaths = append(pluginPaths, strings.Split(cfg.agePluginPath, string(os.PathListSeparator))...)
	}
	if v := os.Getenv("AGE_PLUGIN_PATH"); v != "" {
		pluginPaths = append(pluginPaths, strings.Split(v, string(os.PathListSeparator))...)
	}
	if AgePluginPath != "" {
		pluginPaths = append(pluginPaths, strings.Split(AgePluginPath, string(os.PathListSeparator))...)
	}
	if len(pluginPaths) > 0 {
		combined := strings.Join(pluginPaths, string(os.PathListSeparator))
		_ = os.Setenv("PATH", combined+string(os.PathListSeparator)+os.Getenv("PATH"))
	}

	log.Default().SetOutput(os.Stderr)
	log.Default().SetFlags(0) // suppress timestamps for deterministic output

	in := io.Reader(os.Stdin)
	inputDesc := "stdin"

	out := io.Writer(os.Stdout)
	outputDesc := "stdout"

	enc := json.NewEncoder(out)
	header := Header{
		"OpenTofu-External-Encryption-Method",
		1,
	}
	if err := enc.Encode(header); err != nil {
		log.Fatalf("Failed to write %s: %v", outputDesc, err)
	}

	dec := json.NewDecoder(in)
	var inputData Input
	if err := dec.Decode(&inputData); err != nil {
		log.Fatalf("Failed to read %s: %v", inputDesc, err)
	}

	var (
		outputPayload []byte
		opErr         error
	)
	if cfg.mode == modeEncrypt {
		outputPayload, opErr = ageEncryptPayload(&cfg, inputData.Payload)
		if opErr != nil {
			log.Fatalf("Failed to encrypt payload: %v", opErr)
		}
	}
	if cfg.mode == modeDecrypt {
		outputPayload, opErr = ageDecryptPayload(&cfg, inputData.Payload)
		if opErr != nil {
			log.Fatalf("Failed to decrypt payload: %v", opErr)
		}
	}

	output := Output{
		Payload: outputPayload,
	}
	if err := enc.Encode(output); err != nil {
		log.Fatalf("Failed to write %s: %v", outputDesc, err)
	}
}

func ageEncryptPayload(cfg *Config, payload []byte) ([]byte, error) {
	if len(cfg.ageRecipients) == 0 {
		return nil, errors.New("no recipients specified")
	}
	recipients := make([]age.Recipient, 0, len(cfg.ageRecipients))
	for r := range cfg.ageRecipients {
		parsed, err := parseRecipientString(r)
		if err != nil {
			return nil, fmt.Errorf("invalid recipient %q: %w", r, err)
		}
		recipients = append(recipients, parsed)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt payload: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return nil, fmt.Errorf("failed to write payload: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed to close encrypted writer: %w", err)
	}
	return buf.Bytes(), nil
}

func ageDecryptPayload(cfg *Config, payload []byte) ([]byte, error) {
	if cfg.ageIdentity == "" {
		return nil, errors.New("no identity specified")
	}
	identities, err := parseIdentityList(strings.NewReader(cfg.ageIdentity))
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(payload), identities...)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %w", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted payload: %w", err)
	}
	return out, nil
}

func parseRecipientString(s string) (age.Recipient, error) {
	if strings.HasPrefix(s, "age1") && strings.Count(s, "1") > 1 {
		return plugin.NewRecipient(s, &plugin.ClientUI{})
	}
	return age.ParseX25519Recipient(s)
}

func parseIdentityList(f io.Reader) ([]age.Identity, error) {
	var ids []age.Identity
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, err := parseIdentityString(line)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read identities: %v", err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no identities found")
	}
	return ids, nil
}

func parseIdentityString(s string) (age.Identity, error) {
	if strings.HasPrefix(s, "AGE-PLUGIN-") {
		return plugin.NewIdentity(s, &plugin.ClientUI{})
	}
	return age.ParseX25519Identity(s)
}

func parseRecipientsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

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
	args := strings.Fields(os.ExpandEnv(command))
	if len(args) == 0 {
		return "", errors.New("empty command")
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
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
