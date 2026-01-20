# Instructions 


This will create a frontdoor service that will point proof.ivan.mithrilsecurity.io to the content of the storage account.

Running
```
uv run main.py --resource-group-name ivan-fli-multinode --location northeurope --storage_account_name attestationproofs --domain ivan.mithrilsecurity.io
```