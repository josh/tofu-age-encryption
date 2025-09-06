# tofu-age-encryption

tofu-age-encryption provides an external encryption method for [OpenTofu](https://opentofu.org/) using [age](https://age-encryption.org/).

## Usage

1. Provide the age recipient and identity file using either environment variables or CLI flags:

   Environment variables:

    - `AGE_IDENTITY_FILE`: path to your age identity file
    - `AGE_RECIPIENT`: comma-separated list of age recipients

   CLI flags:

    - `--age-identity-file`: path to your age identity file
    - `--age-recipient`: may be provided multiple times or as a comma-separated list of recipients

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
