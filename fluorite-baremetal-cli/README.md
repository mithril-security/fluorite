# Fluorite Baremetal

SEV-SNP CLI setup tool for baremetal deployments. This tool helps set up the host environment and launch confidential guest VMs.

## Commands

- `get-artifacts` - Download release artifacts with optional SLSA provenance verification
- `setup-host` - Set up the host machine for SEV-SNP
- `launch-guest` - Launch a guest VM with optional SEV-SNP confidential computing

## Example

Run at the root of the fluorite repository:

```sh
sudo ./fluorite-baremetal-cli/target/debug/fluorite-baremetal launch-guest \
  --confidential \
  --virtualization-type sev-snp \
  --gpu-setup \
  --network "user,id=vmnic,hostfwd=tcp::9899-:22,hostfwd=tcp::3443-:3443,hostfwd=tcp::6443-:6443,hostfwd=tcp::443-:443,hostfwd=tcp::80-:80"
```

Usage documentation available [here](https://mithril-security.notion.site/Baremetal-Setup-Guide-2fbf92285f5e8083828df3858ea06028).