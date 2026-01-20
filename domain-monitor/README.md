# Domain monitor

Check the attestation of a particular domain.

## Running

The application is ment to be run inside of docker containers. The Dockerfile expects to find the domain-monitor application binary at ./domain-monitor/target/release/domain-monitor.

```
docker build -t domain-monitor -f ./domain-monitor/Dockerfile .

docker run -it --rm -p 8000:8000 \
  -e PORT="8000" \
  -e ATTESTATION_BACKEND="AzureTrustedLaunchVM" \
  -e OPERATOR_CERTIFICATE_B64=$(base64 -w0 ./operator/certificates/cert.pem) \
  -e BUNDLE_HASH=d31a269c356e4bfb8496da4d745fd4663ae44cfba3598f91987271a10a529654 \
  -e OS_MEASUREMENT=$(jq -r .fluoriteos_pcr4 ./platform/gcp-shielded-vm/local-tpm/os-measurement.json) \
  -e STORAGE_URL="https://attest-info.test-heeip.azure.net-safe.dedyn.io/" \
  -e PLATFORM_MEASUREMENTS_PATH="/measurements/measurements_azure.json" \
  --name domain-monitor \
  domain-monitor
```