# Domain monitor

Check the attestation status of a particular domain.

## Running

The application is ment to be run inside of docker containers.

```
VERSION=$(curl -sIX HEAD https://github.com/mithril-security/fluorite/releases/latest | grep -i ^location: | grep -Eo '[0-9]+.[0-9]+.[0-9]+')

docker run -it --rm -p 8000:8000 \
  -e PORT="8000" \
  -e ATTESTATION_BACKEND="SvsmVtpm" \
  -e OPERATOR_CERTIFICATE_B64=$(base64 -w0 ./operator/certificates/cert.pem) \
  -e BUNDLE_HASH=$(sha256sum ./packages/zarf-package-ray-amd64-0.1.0.tar.zst | awk '{ print $1 }') \
  -e OS_MEASUREMENT=$(jq -r .fluoriteos_pcr4 ./fluorite-os/baremetal-amd-sev/os-measurement.json) \
  -e STORAGE_URL="https://proof.ivan.mithrilsecurity.io/" \
  -e PLATFORM_MEASUREMENTS_PATH="./measurements/measurements_qemu_svsm.json" \
  -e OS_DISK_URL="https://storage.googleapis.com/fluorite/$VERSION/fluorite-os/cloud-vtpm/disk.raw" \
  -e PROVISIONING_PACKAGE_URL="https://storage.googleapis.com/fluorite/$VERSION/packages/zarf-package-nginx-amd64-0.1.0.tar.zst" \
  --name domain-monitor \
  fluorite.azurecr.io/domain-monitor:$VERSION
```

More documentation available [here](https://mithril-security.notion.site/The-Domain-Monitor-2fbf92285f5e808f8c89ca145586775a).