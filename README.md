# Fluorite

We have developed a framework for running distributed enclave applications that relies on Kubernetes.

## 📚 Documentation

Documentation is live and available on our Notion page [here](https://mithril-security.notion.site/).

### Repository structure

```ini
├── Earthfile # Instructions for Earthly on how to build the os disk image of FluoriteOS and necessary binaries
├── README.md # This file you're reading now
├── attestation-transparency-service # The attestation transparancy service
├── domain-monitor # The domain monitor service
├── fluorite-baremetal-cli # Utility for AMD SEV-SNP baremetal deployments
├── gcp-notarizer-os # The FluoriteOS for GCP
├── gcp-shielded-vm-notarizer # The Notarizer for GCP
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
│   ├── fluorite-azure-cli        # CLI for creating VMs on Azure
│   ├── fluorite-cli              # Main CLI for generating certificates and provisioning clusters
│   ├── fluorite-gcp-cli          # CLI for creating VMs on GCP
│   ├── packages                  # Zarf deployment packages (nginx, ray, etc.)
│   ├── setup-attestation-infra   # Utility for setting up the attestation infra
│   └── azure-disk-upload         # Utility for uploading raw disk images to Azure
├── os-base  # The FluoriteOS for Azure/Baremetal platforms
└── scripts # Utility scrips used by the Github Actions
```
