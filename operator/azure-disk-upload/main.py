from azure.identity import AzureCliCredential
from azure.core.exceptions import ClientAuthenticationError, ResourceNotFoundError
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from datetime import datetime, timedelta, timezone

from azure.mgmt.resource.resources.models import ResourceGroup
from azure.mgmt.compute.models import (
    CommunityGalleryInfo,
    GallerySharingPermissionTypes,
    SharingProfile,
    Gallery,
    GalleryImage,
    GalleryImageIdentifier,
    OperatingSystemTypes,
    GalleryImageFeature,
    OperatingSystemStateTypes,
    HyperVGeneration,
    GalleryImageVersion,
    GalleryImageVersionStorageProfile,
    GalleryOSDiskImage,
    GalleryDiskImageSource,
    ImageVersionSecurityProfile,
    GalleryImageVersionUefiSettings,
    UefiKey,
    UefiKeyType,
    UefiKeySignatures,
    UefiSignatureTemplateName,
    GalleryImageVersionPublishingProfile,
    ReplicationMode,
    TargetRegion,
)
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import (
    StorageAccountCreateParameters,
    Sku as SkuStorage,
    Kind,
    KeyType,
    MinimumTlsVersion,
    EncryptionService,
    EncryptionServices,
    KeySource,
    Encryption,
    BlobContainer,
)

from azure.storage.blob import BlobServiceClient
from azure.storage.blob import generate_blob_sas, BlobSasPermissions

import logging
import sys
import argparse
import shutil
import os
import subprocess
import json
import base64
from cryptography import x509
import random
import string
from cryptography.hazmat.primitives.serialization import Encoding

logging.basicConfig(
    format="{asctime} - {levelname} - {message}",
    style="{",
    datefmt="%Y-%m-%d %H:%M",
    level=logging.INFO,
)

logging.getLogger("azure").setLevel(logging.WARNING)


def generate_random_string(length: int):
    """Generate a random string of lowercase alphabetic characters."""
    return "".join(random.choices(string.ascii_lowercase, k=length))


def qemu_disk_size(path: str):
    out = subprocess.run(
        ["qemu-img", "info", "--output", "json", path],
        check=True,
        capture_output=True,
        text=True,
    )

    j = json.loads(out.stdout)

    return j["virtual-size"]


def main(
    os_disk_path: str,
    resource_group_name: str,
    location: str,
    storage_account_name: str,
    container_name: str,
    gallery_name: str,
    offer: str,
    publisher: str,
    sku: str,
    target_regions: list[str],
    gallery_image_name: str,
    image_version: str,
):
    credential = AzureCliCredential()

    logging.info("Getting subscription ID")
    subscription_client = SubscriptionClient(credential=credential)
    try:
        subscription_id = (
            subscription_client.subscriptions.list().next().subscription_id
        )
    except ClientAuthenticationError:
        logging.error("Could not get subscription ID. Did you `az login`? Exiting")
        sys.exit(1)

    if not subscription_id:
        logging.error("`subscription_id` is None. Exiting")
        sys.exit(1)

    logging.info(f"Success. Subscription ID: {subscription_id}")

    logging.info(
        f"Validating location '{location}' and target regions {target_regions}"
    )
    valid_locations = [
        loc.name
        for loc in subscription_client.subscriptions.list_locations(
            subscription_id=subscription_id
        )
    ]

    if location not in valid_locations:
        logging.error(f"The selected location is not a valid location {location}")
        logging.error(
            "Please use a valid location name such as: westeurope, eastus2,..."
        )
        sys.exit(1)

    if any([r not in valid_locations for r in target_regions]):
        invalid = [r not in valid_locations for r in target_regions]
        invalid_regions = [
            loc for not_valid, loc in zip(invalid, target_regions) if not_valid
        ]

        logging.error(
            f"The selected target_regions contain a location which is not valid: {','.join(invalid_regions)}"
        )
        logging.error(
            "Please use a valid location name such ass: westeurope, eastus2,..."
        )
        sys.exit(1)

    logging.info(f"Successfully validated location and target regions")

    resource_client = ResourceManagementClient(credential, subscription_id)

    logging.info(
        f"Creating Resource Group {resource_group_name} in location {location}"
    )
    resource_group_parameters = ResourceGroup(location=location)
    resource_client.resource_groups.create_or_update(
        resource_group_name=resource_group_name, parameters=resource_group_parameters
    )

    logging.info(
        f"Successfully created Resource Group {resource_group_name} in location {location}"
    )

    logging.info(
        "Resizing disk to make it suitable for Azure. Making a backup to ./disk.raw ..."
    )

    storage_client = StorageManagementClient(
        credential=credential, subscription_id=subscription_id
    )

    logging.info(f"Creating Storage Account {storage_account_name}")

    encryption_services = EncryptionServices(
        blob=EncryptionService(enabled=True, key_type=KeyType.ACCOUNT),
        file=EncryptionService(enabled=True, key_type=KeyType.ACCOUNT),
    )
    encryption = Encryption(
        services=encryption_services, key_source=KeySource.MICROSOFT_STORAGE
    )
    storage_account_parameters = StorageAccountCreateParameters(
        location=location,
        sku=SkuStorage(name="Standard_RAGRS"),
        kind=Kind.STORAGE_V2,
        allow_blob_public_access=False,
        minimum_tls_version=MinimumTlsVersion.TLS1_2,
        encryption=encryption,
    )
    storage_account = storage_client.storage_accounts.begin_create(
        resource_group_name=resource_group_name,
        account_name=storage_account_name,
        parameters=storage_account_parameters,
    ).result()

    logging.info(f"Success. Created Storage Account {storage_account_name}")

    logging.info(f"Creating Blob container: {container_name}")

    blob_container = storage_client.blob_containers.create(
        resource_group_name,
        storage_account_name,
        container_name,
        BlobContainer(),  # Use the default blob container
    )

    logging.info(f"Success. Created Blob container.")

    if (
        not storage_account.primary_endpoints
        or not storage_account.primary_endpoints.blob
    ):
        logging.info(
            f"Failed. storage_account.primary_endpoints or storage_account.primary_endpoints.blob are empty"
        )
        sys.exit(1)

    logging.info(f"Getting Storage Account keys")

    keys = storage_client.storage_accounts.list_keys(
        resource_group_name=resource_group_name, account_name=storage_account_name
    )

    if not keys or not keys.keys:
        logging.info(f"Failed. No keys for the storage account were retrieved.")
        sys.exit(1)

    account_key = keys.keys[0].value

    logging.info(f"Success. Got Storage Account keys")

    disk_name = f"osdisk-{generate_random_string(5)}.vhd"
    logging.info(f"Generating blob SAS token for disk: {disk_name}")

    # az storage azcopy blob upload \
    #     -c $CONTAINER_NAME \
    #     --account-name $STORAGE_ACCOUNT_NAME \
    #     -s $DISK_PATH \
    #     -d $DISK_NAME

    sas_token = generate_blob_sas(
        account_name=storage_account_name,
        container_name=container_name,
        blob_name=disk_name,
        account_key=account_key,
        permission=BlobSasPermissions(write=True, create=True),
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),  # Valid for 1 hour
    )

    sas_url = f"{storage_account.primary_endpoints.blob}{container_name}/{disk_name}?{sas_token}"
    logging.info(f"Success. Generated SAS URL.")

    logging.info(
        "Resizing disk to make it suitable for Azure. Making a backup to ./disk.raw ..."
    )

    dst = "./disk.raw"

    shutil.copyfile(os_disk_path, dst, follow_symlinks=False)

    disk_size = qemu_disk_size(dst)
    logging.info(f"Orignal disk size: {disk_size} bytes")

    mb = 1024 * 1024
    rounded_size = ((disk_size + mb - 1) // mb) * mb
    logging.info("Resizing the disk using qemu-img resize")
    logging.info(f"Resizing disk to {rounded_size} bytes...")
    subprocess.run(
        ["qemu-img", "resize", "-f", "raw", dst, str(rounded_size)],
        check=True,
        capture_output=True,
        text=True,
    )
    logging.info("Resizing successful")

    path_disk_converted = f"{dst}.vhd"

    # Azure requires subformat=fixed and force_size for VHDs
    logging.info("Converting image using qemu-img convert...")
    subprocess.run(
        [
            "qemu-img",
            "convert",
            "-f",
            "raw",
            "-o",
            "subformat=fixed,force_size",
            "-O",
            "vpc",
            dst,
            path_disk_converted,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    logging.info("Disk successfully resized. Now it's ready for upload.")
    logging.info("Uploading disk...")

    subprocess.run(
        ["azcopy", "copy", "--blob-type", "PageBlob", path_disk_converted, sas_url],
        check=True,
        capture_output=True,
        text=True,
    )

    logging.info("Disk upload with azcopy successful")

    compute_client = ComputeManagementClient(credential, subscription_id)

    # az sig create --resource-group $RESOURCE_GROUP --gallery-name $GALLERY_NAME
    logging.info(f"Creating Gallery: {gallery_name}")
    try:
        gallery = compute_client.galleries.get(resource_group_name, gallery_name)
        logging.info(f"Got Gallery: {gallery_name}")
    except ResourceNotFoundError:
        community_gallery_info = CommunityGalleryInfo(
            publisher_contact="contact@mithrilsecurity.io",
            publisher_uri="https://www.mithrilsecurity.io/",
            eula="https://www.mithrilsecurity.io/",
            public_name_prefix="FluoriteOS",
        )
        sharing_profile = SharingProfile(
            permissions=GallerySharingPermissionTypes.COMMUNITY,
            community_gallery_info=community_gallery_info,
        )
        gallery = Gallery(location=location, sharing_profile=sharing_profile)
        compute_client.galleries.begin_create_or_update(
            resource_group_name=resource_group_name,
            gallery_name=gallery_name,
            gallery=gallery,
        ).result()

        logging.info(f"Created Gallery: {gallery_name}")

    # az sig image-definition create \
    #     --resource-group $RESOURCE_GROUP \
    #     --gallery-name $GALLERY_NAME \
    #     --gallery-image-definition $GALLERY_IMAGE_NAME \
    #     --publisher $PUBLISHER \
    #     --sku $IMAGE_SKU \
    #     --offer $OFFER \
    #     --os-type "Linux" \
    #     --hyper-v-generation V2 \
    #     --features SecurityType=TrustedLaunchAndConfidentialVMSupported \
    #     --os-state Specialized

    logging.info(f"Creating Gallery Image: {gallery_image_name}")

    identifier = GalleryImageIdentifier(publisher=publisher, offer=offer, sku=sku)
    features = [
        GalleryImageFeature(
            name="SecurityType", value="TrustedLaunchAndConfidentialVMSupported"
        )
    ]
    gallery_image = GalleryImage(
        location=location,
        identifier=identifier,
        features=features,
        os_type=OperatingSystemTypes.LINUX,
        os_state=OperatingSystemStateTypes.SPECIALIZED,
        hyper_v_generation=HyperVGeneration.V2,
    )
    compute_client.gallery_images.begin_create_or_update(
        resource_group_name=resource_group_name,
        gallery_name=gallery_name,
        gallery_image_name=gallery_image_name,
        gallery_image=gallery_image,
    ).result()

    logging.info(f"Created Gallery Image: {gallery_image_name}")

    # az sig image-version create \
    #     --resource-group $RESOURCE_GROUP \
    #     --gallery-name $GALLERY_NAME
    #     --gallery-image-definition $GALLERY_IMAGE_NAME \
    #     --gallery-image-version $IMAGE_VERSION \
    #     --os-vhd-storage-account $STORAGE_ACCOUNT_ID \
    #     --os-vhd-uri $BLOB_URL

    logging.info(f"Creating image with version: {image_version}")

    gallery_image_version_name = image_version
    uri = f"{storage_account.primary_endpoints.blob}{container_name}/{disk_name}"

    source = GalleryDiskImageSource(storage_account_id=storage_account.id, uri=uri)
    os_disk_image = GalleryOSDiskImage(source=source)
    storage_profile = GalleryImageVersionStorageProfile(os_disk_image=os_disk_image)

    # Similar to https://github.com/edgelesssys/uplosi/blob/83ad0a664ee1a444bbc2a3ffd5e8b644560ab527/azure/uploader.go#L688
    filtered_target_regions = [
        TargetRegion(name=location, regional_replica_count=1)
    ]  # The location of the AzureComputeGallery is the primary region
    for region in target_regions:
        if region == location:
            continue
        filtered_target_regions.append(
            TargetRegion(name=region, regional_replica_count=1)
        )

    publishing_profile = GalleryImageVersionPublishingProfile(
        replica_count=1,
        replication_mode=ReplicationMode.FULL,
        target_regions=filtered_target_regions,
    )
    gallery_image_version = GalleryImageVersion(
        location=location,
        storage_profile=storage_profile,
        publishing_profile=publishing_profile,
    )
    image_version = compute_client.gallery_image_versions.begin_create_or_update(
        resource_group_name=resource_group_name,
        gallery_name=gallery_name,
        gallery_image_name=gallery_image_name,
        gallery_image_version_name=gallery_image_version_name,
        gallery_image_version=gallery_image_version,
    ).result()

    logging.info(f"Created image version: {image_version.id}")


def cli():
    parser = argparse.ArgumentParser(
        description="Utility that given an raw disk image, uploads it to Azure Cloud Platform and creates an VM image version that can be used to spawn VMs with that disk!"
    )

    parser.add_argument(
        "--os-disk-path",
        help="Path to the mithril-os raw disk image",
        type=str,
        required=True,
    )
    parser.add_argument(
        "--resource-group-name",
        help="Name of the resource group",
        type=str,
        required=True,
    )
    parser.add_argument(
        "--location",
        help="Location where the Azure resources will be created",
        type=str,
        required=True,
    )
    parser.add_argument(
        "--storage-account-name",
        help="Name of the Storage Account where the disk will be uploaded. If it does not exists, it will create one called `diskstorageaccount`. Default value: `diskstorageaccount`.",
        type=str,
        required=False,
        default="diskstorageaccount",
    )
    parser.add_argument(
        "--container-name",
        help="Name of the Container in the Storage Account where the disk will be uploaded. If it does not exists, it will create one called `vhds`. Default value: `vhds`.",
        type=str,
        required=False,
        default="vhds",
    )
    parser.add_argument(
        "--gallery-name",
        help="Name of the Azure Compute Gallery. If it does not exists, it will create one called `FluoriteGallery`. Default value: `FluoriteGallery`",
        type=str,
        required=False,
        default="FluoriteGallery",
    )
    parser.add_argument(
        "--offer",
        help="The VM image definition publisher offer. Default value `Linux`",
        type=str,
        required=False,
        default="Linux",
    )
    parser.add_argument(
        "--publisher",
        help="The VM image definition publisher. Default value `MithrilSecurity`",
        type=str,
        required=False,
        default="MithrilSecurity",
    )
    parser.add_argument(
        "--sku",
        help="The VM image definition publisher SKU",
        type=str,
        required=False,
        default="MySku",
    )
    parser.add_argument(
        "--gallery-image-name",
        help="The VM image definition publisher name",
        type=str,
        required=False,
        default="FluoriteOS",
    )

    parser.add_argument(
        "--target-regions",
        help="List of the target regions where the VM image version will be replicated. By default it is replicated in the location of the AzureComputeGallery.",
        type=str,
        nargs="+",
        required=True,
    )

    parser.add_argument(
        "--version",
        help="The image version in semver format (e.g., 1.0.0)",
        type=str,
        required=True,
    )

    args = parser.parse_args()

    if not os.path.isfile(args.os_disk_path):
        parser.error(
            f"The path to the disk does not exist: {args.os_disk_path}.\nMake sure the path is correct and that it points to a file and run again."
        )

    required_binaries = ["qemu-img", "azcopy"]
    missing_binaries = []

    for binary in required_binaries:
        if shutil.which(binary) is None:
            missing_binaries.append(binary)

    if missing_binaries:
        logging.error(f"Missing required dependencies: {', '.join(missing_binaries)}")
        logging.error(
            "Please install them or ensure they are in your PATH. See README.md"
        )
        sys.exit(1)

    main(
        os_disk_path=args.os_disk_path,
        resource_group_name=args.resource_group_name,
        location=args.location,
        storage_account_name=args.storage_account_name,
        container_name=args.container_name,
        gallery_name=args.gallery_name,
        offer=args.offer,
        publisher=args.publisher,
        sku=args.sku,
        target_regions=args.target_regions,
        gallery_image_name=args.gallery_image_name,
        image_version=args.version,
    )

if __name__ == "__main__":
    cli()