# GCP Shielded VM Notarizer

A service that runs on a GCP Confidential VM (CVM) to notarize the identity of GCE Shielded VMs.

## Problem Statement

GCE Shielded VMs have vTPMs with measured boot capabilities, but unlike GCP Confidential VMs, their Attestation Keys (AK) are not backed by an AK certificate chain. This makes it difficult to establish trust in the vTPM quotes from Shielded VMs.

## Solution

This notarizer service bridges that gap by:

1. **Running on a GCP CVM**: The notarizer runs on a Confidential VM (AMD SEV) which has a proper AK certificate chain signed by Google's CA.
2. **Generating an (attestation backed) signing key**: At startup, the service generates a signing key and includes the public key in its TPM-backed event log. This binds the signing key to the platform state.
3. **Notarizing Shielded VM identities**: When requested, the service:

   - Calls GCP's `getShieldedVmIdentity` API for the specified Shielded VM
   - Signs a message with the response (the shielded instance identity) of the API
   - Returns both the signed identity and its own attestation

## Verification Flow 

Verifiers can establish trust through:

1. **Verify notarizer attestation**: Validate the CVM attestation document against Google's AK CA root certificate using `gcp-cvm-attestation`'s verification.
2. **Verify event log**: Replay the event log and verify it matches PCR 8 in the attestation quote. Extract the signing public key from the `NotarizerStarted` event.
3. **Verify signed message**: Use the `MessageVerifyingKey` from the attestation to verify the `SignedMessage` containing the Shielded VM identity.
4. **Verify a Shielded VM**: Now that we got the endorsement of the AK via the notarized `getShieldedVmIdentity`, we can use it to verify the GCP shielded VM quote.

## API Endpoints

### `GET /health`

Health check endpoint.

**Response:**

```json
{
  "status": "ok",
  "service": "gcp-shielded-vm-notarizer"
}
```

### `GET /attestation`

Get the notarizer's CVM attestation document with event log.

**Response:**

```json
{
  "notarizer_attestation": {
    "cvm_attestation": {
      "quote": { ... },
      "ak_cert_chain": ["<base64>", "<base64>", "<base64>"]
    },
    "event_log": {
      "events": ["<serialized events>"]
    },
    "verifying_key": { ... }
  }
}
```

### `POST /notarize`

Notarize a Shielded VM's identity.

**Headers:**

- `Content-Type: application/json`

**Request:**

```json
{
  "project": "my-gcp-project",
  "zone": "us-central1-a",
  "instance": "my-shielded-vm",
}
```

**Response:**

```json
{
  "notarized_identity": {
    "signed_message": {
      "inner": "<signed message bytes>"
    },
    "payload": {
      "shielded_vm_identity": {
        "kind": "compute#shieldedVmIdentity",
        "signingKey": { "ekPub": "..." },
        "endorsementKey": { "ekPub": "..." }
      },
      "notarized_at": "2024-01-15T10:30:00Z",
      "project": "my-gcp-project",
      "zone": "us-central1-a",
      "instance": "my-shielded-vm"
    }
  },
  "notarizer_attestation": { ... }
}
```

## Event Log Structure

The notarizer eventlog is backed by PCR 8. Only event is 
**NotarizerStarted**: Logged once at startup. Made of :

   - `signing_public_key`: The public key used for signing (hex)

## Building

```bash
cargo build --release
```

## Running

The service must be run on a GCP Confidential VM with:

- vTPM enabled and accessible at `/dev/tpmrm0`
- `creator-certificate` in the GCP instance metadata (the server will only respond to user authenticated with this client-side certificate)
- Appropriate IAM permissions and network access to call Google Compute Engine API endpoint `getShieldedVmIdentity`

```bash
./gcp-shielded-vm-notarizer --listen 0.0.0.0:443
```

## Required IAM Permissions

The service account running the notarizer needs:

- `compute.instances.getShieldedVmIdentity` on target instances

## Security Considerations

1. __Project Restriction__: In production, set `ALLOWED_PROJECT` to prevent the notarizer from being used to query arbitrary projects.
2. **CVM Security**: The security of this system relies on the trustworthiness of GCP Confidential VMs and their attestation chain. gcp-notarizer-os production image are built for that
3. **Signing Key**: The signing key is ephemeral and regenerated on each service restart. The key is bound to the platform state via the TPM event log.

## Trust Chain

```ini
GCP AK Root CA (Google)
    └── Intermediate CA
        └── AK Cert (in CVM vTPM)
            └── TPM Quote (includes PCR 8 = hash(event_log))
                └── Event Log
                    └── NotarizerStarted { signing_public_key }
                        └── SignedMessage<NotarizedShieldedVmIdentityPayload>
                            └── Shielded VM Identity (from getShieldedVmIdentity API)
```

---