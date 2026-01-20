# client

This example application demonstrates connecting to a cluster provsioned with the nginx package, and requesting three times the index page. It requests the index three times, as in the original nginx package thre are three replicas of the nginx deployment.

In order to try it out, change the IP address in the source code with the one of your master node, compile and run:
```
cargo run --release -- \
  --master-url https://chat.ivan.mithrilsecurity.io/ \
  --operator-certificate-path ../../../operator/certificates/cert.pem \
  --bundle-hash $(sha256sum ../../../packages/zarf-package-nginx-amd64-1.0.0.tar.zst | awk '{print $1}')\
  --os-measurement $(jq -r .fluoriteos_pcr4 ../../../fluorite-os/cloud-vtpm/os-measurement.json) \
  --platform-measurements-path ../../../measurements/measurements_azure.json \
  --blob-storage-url https://proofs.demo.mithrilsecurity.io \
  --attestation-backend "AzureConfidentialVM"
```

The blob storage url is optional.