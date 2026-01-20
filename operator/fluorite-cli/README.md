# Fluorite CLI

This is the main Fluorite CLI. It is used by operators to generate certificates and provision clusters.

## Commands

The CLI provides two main commands:

```sh
Usage: fluorite <COMMAND>

Commands:
  generate-certificates  Generate self-signed operator certificates (cert.pem and key.pem)
  deploy                 Deploy a zarf package to a cluster
  help                   Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Generate Certificates

Generate a self-signed certificate to be used by the operator. This will create `cert.pem` (public key) and `key.pem` (private key) in the selected directory.

```sh
Usage: fluorite generate-certificates [OPTIONS] --cert-directory-path <CERT_DIRECTORY_PATH>

Options:
      --cert-directory-path <CERT_DIRECTORY_PATH>
          Path where the `cert.pem` and `key.pem` files will be created
  -f, --force
          Overwrite existing files without prompting
  -h, --help
          Print help
```

Example:

```sh
cargo run --release -- generate-certificates --cert-directory-path ./certificates
```

To overwrite existing certificates, include the `--force` flag:

```sh
cargo run --release -- generate-certificates --cert-directory-path ./certificates --force
```

## Deploy

Deploy a zarf package to provision a cluster.

```sh
Usage: fluorite deploy [OPTIONS] --zarf-package-path <ZARF_PACKAGE_PATH> --os-measurement <OS_MEASUREMENT> --platform-measurements-path <PLATFORM_MEASUREMENTS_PATH> --operator-cert-path <OPERATOR_CERT_PATH> --operator-private-key-path <OPERATOR_PRIVATE_KEY_PATH> --cluster-file-path <CLUSTER_FILE_PATH> --attestation-backend <ATTESTATION_BACKEND>

Options:
      --zarf-package-path <ZARF_PACKAGE_PATH>
          Path to the zarf package used to provision the cluster
      --os-measurement <OS_MEASUREMENT>
          Hex encoded string of the Golden PCR4 of FluoriteOS
      --platform-measurements-path <PLATFORM_MEASUREMENTS_PATH>
          Path to the file containing the golden platform measurements
      --operator-cert-path <OPERATOR_CERT_PATH>
          Path to the operator PEM encoded public certificate
      --operator-private-key-path <OPERATOR_PRIVATE_KEY_PATH>
          Path to the PKCS #8 PEM encoded operator private key
      --cluster-file-path <CLUSTER_FILE_PATH>
          Path to the cluster.json file containing the cluster configuration
      --deployment-config-path <DEPLOYMENT_CONFIG_PATH>
          Optional path to the file containing the variables used during deployment. Example: https://docs.zarf.dev/ref/config-files/#config-file-examples
      --attestation-backend <ATTESTATION_BACKEND>
          The attestation backend to use to verify the attestation received from the enclave
      --deployment-size-bytes <DEPLOYMENT_SIZE_BYTES>
          The size of the deployment, it defaults to 100GB. It's how much disk space the deployment needs [default: 107374182400]
  -h, --help
          Print help
```

See how you can use the `fluorite-cli` to provison your cluster [here](https://mithril-security.notion.site/Provisioning-2fbf92285f5e80928af8f09e5c13a003).