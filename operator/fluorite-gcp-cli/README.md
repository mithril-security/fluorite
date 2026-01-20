# GCP VM CLI

Command-line tool to provision GCP Shielded VMs with attestation support using a Confidential VM notarizer.

## Overview

This script orchestrates the deployment of:

1. **A GCP Confidential VM (CVM)** running the notarizer service (from pre-built OS image)
2. **GCP Shielded VMs** running the multinode provisioning server (from pre-built OS image or Ubuntu)

The notarizer on the CVM endorses the Shielded VMs' attestation keys, allowing them to be verified through the CVM's trusted certificate chain.

## Prerequisites

- Python 3.10+
- [uv](https://github.com/astral-sh/uv) installed
- Google Cloud SDK (`gcloud`) installed and authenticated
- **Built notarizer OS image**: Run `earthly +gcp-notarizer-os` to produce `platform/gcp-cvm-notarizer/image.raw`
- **Built shielded VM OS image** (optional): Build a custom image for shielded VMs
- Operator certificate and private key (generated with `fluorite generate-certificates`)

## Usage

```bash
# First, build the notarizer OS image
earthly +gcp-notarizer-os

# Deploy Notarizer CVM + Shielded VMs for the cluster 
uv run main.py \
    --project=my-gcp-project \
    --zone=europe-west10-a \
    --subnet=my-subnet \
    --bucket=my-gcs-bucket \
    --operator-cert-path=./operator.pem \
    --operator-key-path=./operator-key.pem \
    --image-shielded-vm-path=./fluorite-os/cloud-vtpm/image.raw \
    --num-servers=1
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--project` | Yes | GCP project ID |
| `--zone` | Yes | GCP zone (e.g., `europe-west10-a`) |
| `--subnet` | Yes | GCP subnet name |
| `--bucket` | Yes | GCS bucket for storing OS images |
| `--operator-cert-path` | Yes | Path to the operator PEM certificate |
| `--operator-key-path` | Yes | Path to the operator private key |
| `--image-notarizer-path` | No | Path to notarizer image.raw (default: `gcp-cvm-notarizer/disk.raw`) |
| `--image-shielded-vm-path` | No | Path to Shielded VM image.raw (default: `fluorite-os/cloud-vtpm/disk.raw`) |
| `--num-servers` | No | Number of server nodes (default: 1) |
| `--num-agents` | No | Number of agent nodes (default: 0) |
| `--cvm-name` | No | Name for the CVM (default: `notarizer-cvm`) |
| `--skip-cleanup` | No | Keep the notarizer CVM running after deployment |

## How It Works

1. **Upload Notarizer Image**: Compresses and uploads the notarizer OS image to GCS
2. **Create Notarizer GCP Image**: Creates a Compute Engine image with SEV support
3. **Upload Shielded VM Image** (optional): If `--image-shielded-vm-path` is provided, uploads and creates a GCP image
4. **Create CVM**: Creates a Confidential VM with AMD SEV using the notarizer image
5. **Wait for Service**: Waits for the notarizer service to become available
6. **Create Shielded VMs**: Creates Trusted Launch VMs with vTPM enabled
7. **Get Endorsements**: For each Shielded VM, requests a notarizer endorsement
8. **Cleanup Notarizer**: Deletes the notarizer CVM (after all endorsements are obtained)
9. **Update Metadata**: Adds the endorsement to each VM's userdata metadata

## Output

The script outputs:

- `cluster.json` - Cluster configuration with server/agent addresses
- `endorsements.json` - All notarizer endorsements for each VM

```json
{
  "servers": [
    {"name": "master-server", "address": "34.x.x.x"}
  ],
  "agents": []
}
```

## Security

- The notarizer uses TLS with client certificate authentication
- Only clients presenting the operator certificate can request endorsements
- The notarizer runs on a Confidential VM with hardware-backed attestation
- The notarizer CVM is deleted after endorsements are obtained (unless `--skip-cleanup`)
