# Domain monitor

Check the attestation of a particular domain.

## Running

The application is ment to be run inside of docker containers. The Dockerfile expects to find the domain-monitor application binary at ./domain-monitor/target/release/domain-monitor.

```
VERSION="0.0.0-testing-20260130183250"

docker run -it --rm -p 8000:8000 \
  -e PORT="8000" \
  -e ATTESTATION_BACKEND="AzureTrustedLaunchVM" \
  -e OPERATOR_CERTIFICATE_B64=$(base64 -w0 ./operator/certificates/cert.pem) \
  -e BUNDLE_HASH=699e45f24f6adb271764e224294cd290d8fe5312101b53e231290e4ba1df3ef9
  -e OS_MEASUREMENT=97023ad67ba2d276c7cb430508153ce8276798b802bb992a80d9e8cba6f497e1 \
  -e STORAGE_URL="https://proof.ivan.mithrilsecurity.io/" \
  -e PLATFORM_MEASUREMENTS_PATH="./measurements/measurements_azure.json" \
  -e OS_DISK_URL="https://storage.googleapis.com/fluorite/$VERSION/fluorite-os/cloud-vtpm/disk.raw" \
  -e PROVISIONING_PACKAGE_URL="https://storage.googleapis.com/fluorite/$VERSION/packages/zarf-package-nginx-amd64-1.0.0.tar.zst" \
  --name domain-monitor \
  mycr32671.azurecr.io/domain-monitor:$VERSION
```