# setup-attestation-infra 

## Prerequisites

- azcli handle logging into Azure

```sh
curl -sL https://aka.ms/InstallAzureCLIDeb | bash
```


This will create a frontdoor service that will point `https://proofs.demo.mithrilsecurity.io` to the content of the storage account.

Running
```
uv run main.py \
    --resource-group-name ivan-fli-multinode \
    --location northeurope \
    --storage_account_name attestationproofs \
    --zone-name demo.mithrilsecurity.io
```

Proofs will be accessible at `https://proofs.demo.mithrilsecurity.io/by-hash-pub-key/<HASH>`.