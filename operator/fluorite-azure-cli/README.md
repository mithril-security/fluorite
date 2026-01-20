# fluorite-azure-cli

Command line tool to create virtual machines on Azure Cloud. 

## Prerequisites

- Python 3.10+
- [uv](https://github.com/astral-sh/uv) installed
- azcli handle logging into Azure

```sh
curl -sL https://aka.ms/InstallAzureCLIDeb | bash
```

Here is an example command that spawns two Standard_NC24ads_A100_v4 vms in the MyResourceGroup resource group.
The vms will have the AzureTrustedLaunchVM security type, and one will be a control plane node and one will be an agent node.

```
az login # Successfully  login
VERSION=$(curl -sIX HEAD https://github.com/mithril-security/fluorite/releases/latest | grep -i ^location: | grep -Eo '[0-9]+.[0-9]+.[0-9]+')
VERSION_FORMATTED="${VERSION//./-}"

uv tool install .

fluorite-azure \
    --location francecentral \
    --resource-group-name MyResourceGroup \
    --vm-type Standard_NC24ads_A100_v4 \
    --vm-security-type AzureTrustedLaunchVM \
    --num-control-plane-nodes 1 \
    --num-agent-nodes 1 \
    --operator-pem-cert-path ../certificates/cert.pem \
    --community-gallery-image-id /CommunityGalleries/FluoriteOS-34c46669-97d8-4ac7-adcf-2d18e6662797/Images/fluorite-os-$VERSION_FORMATTED/Versions/1.0.0

# OR

uv run main.py ...
```

There is a distinction between the control plane nodes and agent nodes as they have different sets of open ports.
The control plane nodes have the following inbound open ports:
```
TCP: 443, 3443, 6443, 10250, 51820
UDP: 51821
```

The agent nodes have the following inbound open ports:
```
TCP: 443, 3443
```

The ports `6443, 10250, 51820, 51821` are the ones required by K3s to work with Wireguard enabled.
The port `3443` is the port required by the provisioning server program.
The port `443` is the port on which the application running on the cluster is listening on.
