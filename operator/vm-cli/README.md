# VM CLI

Command line tool to create virtual machines on Azure Cloud. 

## Binary dependencies

- azcli handle logging into Azure

```sh
curl -sL https://aka.ms/InstallAzureCLIDeb | bash
```

Here is an example command:
```
az login # Successfully  login
uv run main.py \
    --location francecentral \
    --resource-group-name EndToEndTest \
    --vm-type Standard_NC24ads_A100_v4 \
    --vm-security-type TrustedLaunchVM \
    --num-control-plane-nodes 1 \
    --num-agent-nodes 1 \
    --operator-pem-cert-path ../certificates/cert.pem \
    --image-resource-id /subscriptions/172eac35-f783-4876-b361-544e7b8900e9/resourceGroups/fluorite-azure-registries-eastus2/providers/Microsoft.Compute/galleries/FluoriteGallery/images/FluoriteOS
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
