# Fluorite

An operating system developed by Mithril Security.

## Requirements

In order to build the os images you will need:
-  [Earthly](https://earthly.dev/get-earthly)


## Installation Details

Get [Earthly](https://earthly.dev/get-earthly):
```bash
$ sudo /bin/sh -c 'wget https://github.com/earthly/earthly/releases/latest/download/earthly-linux-amd64 -O /usr/local/bin/earthly && chmod +x /usr/local/bin/earthly && /usr/local/bin/earthly bootstrap --with-autocomplete'
```

Get the attestation submodule. The branch used is `QEMU-attestation`.
```bash
git submodule init 
git submodule update
```

## Building the OS Images

In order to build an os image with TPM support and NVIDIA drivers use the following command:
```bash
earthly -i -P +mithril-os-tpm --OS_CONFIG='config-tpm.yaml'
```


- `debug`: is insecure and should be used only during development. By default is set to `false` and produces a production ready image. If set to `true`, it installs utility tools such as curl, vim, grep,... and it allows enables console access via a root user with password "root" and to ssh as root.
- `nvidiaDriver`: installs nvidia drivers `nvidia-driver-580-open` and the `nvidia-container-toolkit`.
- `snpBareMetal`: Uses the coconut svsm kernel. Needed for the AMD SEV-SNP Baremetal platform.
- `outputDir`: Choose where the `image.raw` will be saved. By default it's `platform/gcp-shielded-vm/local-tpm/`.


## Repository structure

```
├── Earthfile # Instructions for Earthly on how to build the os disk image of FluoriteOS 
├── README.md # This file you're reading now
├── attestation-transparency-service # The attestation transparancy service
├── domain-monitor # The domain monitor service
├── fluorite-cli # Utility for the AMD SEV SNP Platform
├── libraries                     # Libraries necessary for the provisioning server program and operator utilities 
│   ├── attestation               # Library implementing the attestation backend
│   ├── attested-server-verifier  # Library implementing the attestation verification steps
│   ├── cloud-helpers             # Helpers for interacting with the Azure Cloud Platform from Rust
│   ├── provisioning-structs      # Shared structs across the code base
├── measurements # Golden PCR measurements for different platforms
├── multinode-provisioning
│   ├── examples         # Example clients that verifies the cluster attestation and connects to it
│   └── server           # The server. Listens from instructions from the operator.
├── operator # Operator utilities
│   ├── generate-certificates-cli # Utility to generate self-signed operator certificates
│   ├── operator-cli              # Utility for provisioning a cluster of virtual machines
│   ├── setup-attestation-infra   # Utility for setting up the attestation infra
│   ├── upload-os-image           # Utility for uploading raw disks images to Azure
│   └── vm-cli                    # Utility to create VMs on Azure with a given VM image version
├── os-base  # The FluoriteOS
└── scripts # Utility scrips used by the Github Actions
```
