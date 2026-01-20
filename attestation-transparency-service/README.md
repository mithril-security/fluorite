# Attestation Transparency Service

An implementation of the [enclave_manager](https://github.com/mithril-security/blindllama-server/tree/rev-proxy-attestation-service/enclave-manager).

## Running

The application is ment to be run inside of docker containers.

The IDENTITY_RESOURCE_ID must be the resource ID of an Azure Managed Identity with permissions to act over a Blob Storage Account. So it must have the Role Storage Account Contributor.

```
VERSION=$(curl -sIX HEAD https://github.com/mithril-security/fluorite/releases/latest | grep -i ^location: | grep -Eo '[0-9]+.[0-9]+.[0-9]+')
AZURE_SUBSCRIPTION_ID="..."
RESOURCE_GROUP="..."
ATTESTATION_STORAGE_ACCOUNT_NAME="..."

docker run -it --rm -p 8000:8000 \
  -e PORT="8000" \
  -e ATTESTATION_BACKEND="SvsmVtpm" \
  -e PASSWORD=36cb577cef052c9b88e717f676e08ff7d8bc757ee70ed3753bfc396cf8044c44 \
  -e OPERATOR_CERTIFICATE_B64=$(base64 -w0 ./operator/certificates/cert.pem) \
  -e BUNDLE_HASH=$(sha256sum ./packages/zarf-package-ray-amd64-1.0.0.tar.zst | awk '{ print $1 }') \
  -e OS_MEASUREMENT=$(jq -r .fluoriteos_pcr4 ./fluorite-os/baremetal-amd-sev/os-measurement.json) \
  -e STORAGE_URL="https://proof.ivan.mithrilsecurity.io/" \
  -e PLATFORM_MEASUREMENTS_PATH="./measurements/measurements_qemu_svsm.json" \
  -e RESOURCE_GROUP_NAME=$RESOURCE_GROUP \
  -e ATTESTATION_STORAGE_ACCOUNT_NAME=$ATTESTATION_STORAGE_ACCOUNT_NAME \
  -e AZURE_SUBSCRIPTION_ID=$AZURE_SUBSCRIPTION_ID \
  -e IDENTITY_RESOURCE_ID="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.ManagedIdentity/userAssignedIdentities/attestation-transparency-service-identity" \
  --name attestation-transparency-service \
  fluorite.azurecr.io/attestation-transparency-service:latest
```

More documentation available [here](https://mithril-security.notion.site/The-Attestation-Transparency-Service-2fbf92285f5e8011afbac44815be542a).