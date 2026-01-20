# Operator TODO UPDATE

This repository contains the source code of the operator cli. The operator is in charge of provisioning the cluster. 
Here is the help information:
```sh
Usage: operator-cli [OPTIONS] --zarf-package-path <ZARF_PACKAGE_PATH> --os-measurement <OS_MEASUREMENT> --platform-measurements-path <PLATFORM_MEASUREMENTS_PATH> --operator-cert-path <OPERATOR_CERT_PATH> --operator-private-key-path <OPERATOR_PRIVATE_KEY_PATH> --cluster-file-path <CLUSTER_FILE_PATH> --deployment-config-path <DEPLOYMENT_CONFIG_PATH> --attestation-backend <ATTESTATION_BACKEND>

Options:
      --zarf-package-path <ZARF_PACKAGE_PATH>
          Path to the zarf package used to provision the cluster
      --os-measurement <OS_MEASUREMENT>
          Hex encoded string of the Golden PCR4 of FluoriteOS
      --platform-measurements-path <PLATFORM_MEASUREMENTS_PATH>
          Path to the file containing the golden platform measurements
      --operator-cert-path <OPERATOR_CERT_PATH>
          Path to the operator PEM encoded public certificate
      --operator-private-key-path <OPERATOR_PRIVATE_KEY_PATH>
          Path to the PKCS #8 PEM encoded operator private key
      --cluster-file-path <CLUSTER_FILE_PATH>
          Path to the cluster.json file containing the cluster configuration
      --deployment-config-path <DEPLOYMENT_CONFIG_PATH>
          Path to the file containing the variables used during deployment. Example: https://docs.zarf.dev/ref/config-files/#config-file-examples
      --attestation-backend <ATTESTATION_BACKEND>
          The attestation backend to use to verify the attestation received from the enclave
      --deployment-size-bytes <DEPLOYMENT_SIZE_BYTES>
          The size of the deployment, it defaults to 100GB. It's how much disk space the deployment needs [default: 107374182400]
  -h, --help
          Print help
  -V, --version
          Print version
```

An example command to provision a cluster:
```sh
cargo run --release -- \
  --zarf-package-path ../../packages/zarf-package-nginx-amd64-1.0.0.tar.zst \
  --os-measurement $(jq -r .fluoriteos_pcr4 ../../fluorite-os/cloud-vtpm/os-measurement.json) \
  --platform-measurements-path ../../measurements/measurements_azure.json \
  --operator-cert-path ../certificates/cert.pem \
  --operator-private-key-path ../certificates/key.pem \
  --cluster-file-path ../vm-cli/cluster.json \
  --deployment-config-path ./deployment_config.yaml \
  --attestation-backend "AzureTrustedLaunchVM"
```

Before starting to provision a cluster we need to create a json file containing the IPs on the virtual machines running the multinode-provisioning server program.

Here is an example file:
```json

{
  "servers": [
    {
      "name": "master-vm",
      "address": "4.178.49.73",
      "vm_id": "6439c4b8-5c81-4b49-88a7-1ec0bf217e17"
    }
  ],
  "agents": [
    {
      "name": "agent0-vm",
      "address": "4.211.107.212",
      "vm_id": "a15bb5e9-106d-426a-bd49-79d956e6a2a9"
    }
  ]
}
```

In the json there are two root keys: `servers` and `agents`. Each key contains a list of objects (representing the nodes of the cluster) each with the above structure:
- `name`: string with the node name. Can me anything, but must be unique.
- `address`: string of the IP of the VM running the multinode-provisioning server program.
- `vm_id`: id of the virtual machine. It's optional, and it's needed only when using the `AzureTrustedLaunchVM` or `AzureConfidentialVM` Attestation Backends.


The first node in the `servers` list will become the cluster master. There needs to be at least one node in the `server` list to be a valid configuration.


After having created the json cluster definition it is time to create the package that we want to provision the cluster with.
In this repository there are some examples:
- [Nginx](./zarf_nginx/): deployment of an attested nginx application on a Kubernetes cluster.
- [Ollama](./zarf_nginx/): deployment of an attested ollama instance on a Kubernetes cluster.
- [Ray](./zarf_ray/): deployment of an attested ray instance on a Kubernetes cluster.

In order to package a deployment we use Zarf.
For example:
```sh
cd ./zarf_ray/
zarf package create
```

Afterwards it's enough to use the following command to provision a cluster:
``` sh
cargo run --release -- \
  --zarf-package-path ../../packages/zarf-package-ray-amd64-1.0.0.tar.zst \
  --os-measurement $(jq -r .fluoriteos_pcr4 ../../fluorite-os/cloud-vtpm/os-measurement.json) \
  --platform-measurements-path ../../measurements/measurements_azure.json \
  --operator-cert-path ../certificates/cert.pem \
  --operator-private-key-path ../certificates/key.pem \
  --cluster-file-path ./cluster.json \
  --deployment-config-path ./deployment_config.yaml \
  --attestation-backend "AzureConfidentialVM"
```

The certificate directory is a directory containing the public and private key pair of the operator. If the directory is empty, it will create the certificates itself.
Normally the operator certificate is the same certificate contained in the each node IMDS.
The `secrets.json` file in the case of the ray package must contain the Hugging Face key, for example:
```
{
  "HUGGING_FACE_KEY": "hf_YOUR_KEY"
}
```
