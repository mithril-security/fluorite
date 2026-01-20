# GENERATE CERTIFICATES CLI

Command line tool to generate a self-signed certificate to be used by the operator. It will create `cert.pem` containing the public key and `key.pem` private key in selected directory.

Example:
```
cargo run -- --cert-directory-path ./certificates
```

To overwrite existing certificates in the selected directory, include the --force flag. Note: This action will replace any current `cert.pem` and `key.pem` files.