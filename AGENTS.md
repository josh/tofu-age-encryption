# Agents Guide

This project is written in Go and uses Go modules for dependency management. The repository assumes Go 1.24 or newer.

## Setup

1. Install Go 1.24 or later.
2. Install age:

```sh
sudo apt-get update
sudo apt-get install -y age
```

3. Install OpenTofu:

```sh
sudo apt-get install -y tofu
```

4. Download dependencies with:

```sh
$ go mod download
```

## Test Environment

The test suite expects these binaries to be available in the system `PATH`:

- `age`
- `tofu`
- `sh`
- `tail`
- `sed`
- `cat`

## Testing

Run all tests with:

```sh
$ go test ./...
```

To generate a coverage report:

```sh
$ go test -cover ./...
```

The test suite uses [testscript](https://pkg.go.dev/github.com/rogpeppe/go-internal/testscript). Test files live in the `testdata` directory and contain scripts that execute commands and compare their output. These tests differ from standard Go tests because they drive the program via shell-like scripts instead of calling functions directly.

## Formatting

Format code with:

```sh
$ go fmt ./...
```

## Coding Style

Format Markdown files with:

```sh
$ prettier --write *.md
```

## Code Quality

Run vet and static analysis tools before committing:

```sh
$ go vet ./...
```

Optionally run `golangci-lint` for additional checks:

```sh
$ golangci-lint run ./...
```

## Building

Build the project with:

```sh
$ go build ./...
```

## Comments

Keep comments concise. Only add them when they clarify non-obvious logic.
