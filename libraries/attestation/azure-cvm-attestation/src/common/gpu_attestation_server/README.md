# GPU Attestation Server

Rust library that re-implements part of [az-cgpu-onboarding V4.1.5 ](https://github.com/Azure/az-cgpu-onboarding/releases/tag/V4.1.5).
Parts of this library were machine-translated from the original python implementation.

# Running test

```
cargo test
```

By default information level logs are shown.

Alternatevely you can use 
```
RUST_LOG=debug cargo test
```