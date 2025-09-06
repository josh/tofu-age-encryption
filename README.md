# tofu-age-encryption

tofu-age-encryption provides an external encryption method for [OpenTofu](https://opentofu.org/) using [age](https://age-encryption.org/).

OpenTofu encrypts state with a symmetric key derived from a shared passphrase that every operator must share and rotate together. This project replaces that workflow with age's asymmetric key pairs so operators can keep private keys, specify their own recipients, and rotate access without redistributing a secret.

## Usage

1. Ensure the following environment variables are set:

   - `AGE_IDENTITY_FILE`: path to your age identity file
   - `AGE_RECIPIENT`: the corresponding age recipient

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
