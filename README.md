# tofu-age-encryption

tofu-age-encryption provides an external encryption method for [OpenTofu](https://opentofu.org/) using [age](https://age-encryption.org/).

OpenTofu encrypts state with a symmetric key derived from a shared passphrase that every operator must share and rotate together. This project replaces that workflow with age's asymmetric key pairs so operators can keep private keys, specify their own recipients, and rotate access without redistributing a secret.

## Usage

1. Provide the age recipient and identity file using either environment variables or CLI flags:

   Environment variables:
   - `AGE_IDENTITY_FILE`: path to your age identity file
   - `AGE_IDENTITY`: age identity string; supports `file:PATH`, `cmd:COMMAND`, and `command:COMMAND`
   - `AGE_IDENTITY_COMMAND` (alias: `AGE_IDENTITY_CMD`): command whose output is the age identity
   - `AGE_RECIPIENT`: comma-separated list of age recipients
   - `AGE_RECIPIENTS_FILE`: path to a file with newline-separated age recipients

   The following `SOPS_`-prefixed variables are also supported as aliases for compatibility with tools that expect them:
   - `SOPS_AGE_KEY_FILE`: alias for `AGE_IDENTITY_FILE`
   - `SOPS_AGE_KEY`: age identity string
   - `SOPS_AGE_KEY_CMD`: alias for `AGE_IDENTITY_COMMAND`
   - `SOPS_AGE_RECIPIENTS`: alias for `AGE_RECIPIENT` (values from both variables are merged; duplicates are ignored)

   CLI flags:

- `--identity-file`: path to your age identity file
- `--identity`: age identity string or `file:PATH`, `cmd:COMMAND`, `command:COMMAND`
- `--identity-command`: command whose output is the age identity
- `--recipient`: may be provided multiple times or as a comma-separated list of recipients
- `--recipients-file`: path to a file with newline-separated age recipients

2. Configure OpenTofu to use the external method:

```hcl
terraform {
  encryption {
    method "external" "age" {
      encrypt_command = ["tofu-age-encryption", "--encrypt"]
      decrypt_command = ["tofu-age-encryption", "--decrypt"]
    }

    state {
      method   = method.external.age
      enforced = true
    }

    plan {
      method   = method.external.age
      enforced = true
    }
  }
}

resource "random_pet" "example" {}

output "pet" {
  value = random_pet.example.id
}
```

3. Run OpenTofu as usual. The state and plan files are encrypted with the given age recipient:

```sh
$ tofu init
$ tofu apply
```
