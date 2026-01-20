# UPLOAD_OS_IMAGE

Utility that given an raw disk image, uploads it to Azure Cloud Platform and creates an VM image version that can be used to spawn VMs with that disk!
The tool will create the necessary resources on Azure or re-use the ones already present.

This tool will:
1. Create a resource group. If it already exists it will reuse the one already created.
2. Create a Storage Account. By default it will create one called `diskstorageaccount`. If it already exists it will reuse the one already created.
3. Create a Blob Container under that Storage Account. By default it will create one called `vhds`. If it already exists it will reuse the one already created.
4. Get your disk, make a backup copy and resize with `qemu-img` it so that it can be used for spawning VMs on Azure.
5. Get a SAS URL for uploading to the Blob Container and upload the disk to the Blob Container using `azcopy`. 
6. Create a Shared Image Gallery (or Azure compute gallery). By default it will create one called `FluoriteGallery`. If it already exists it will reuse the one already created.
7. It will create a Gallery Image (or VM image definition) in the just created Shared Image Gallery. By default it will create one called `FluoriteOS`. If it already exists it will reuse the one already created. The Image created will be suitable for spawning both VMs with security type TrustedLaunch or ConfidentialVM. The image will have OsType equal to `Linux` and the OsType is equal to `SPECIALIZED`.
8. The first Gallery Image version created will have version name `1.0.0`. The next one will have version `2.0.0`, then `3.0.0` and so on. The image gallery will be replicated to each target region selected and the location of the Gallery Image itself.

## Binary dependencies

- qemu-utils to resize disk to conform to Azure disk specifications
- azcopy - to upload the disk to Azure
- azcli handle logging into Azure

```sh
sudo apt-get install qemu-utils

curl -Lo azcopy.tar https://aka.ms/downloadazcopy-v10-linux
tar xvf azcopy.tar; rm azcopy.tar;
sudo mv azcopy_linux_amd64_*/azcopy /usr/bin/azcopy
rm -rf azcopy_linux_amd64_*

curl -sL https://aka.ms/InstallAzureCLIDeb | bash
```

Running:
```sh
uv run main.py \
    --os-disk-path ../../fluorite-os/cloud-vtpm/disk.raw \
    --resource-group-name fluorite-azure-registries \
    --location eastus2 \
    --target-regions francecentral
```

### Note on target regions

A target region is a geographic location where you choose to replicate and store a copy of your image version.
You can only create a Virtual Machine (VM) in a region where the image version is physically stored. If you want to deploy VMs in both "East US" and "France Central," both must be listed as target regions.
By default the Gallery Image will be live in the location where the the Gallery Image resource is created.
With the command above it will be possible to spawn VMs both in the locations `eastus2` and `francecentral`.
