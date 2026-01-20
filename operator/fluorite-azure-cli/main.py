from azure.identity import AzureCliCredential
from azure.core.exceptions import ClientAuthenticationError
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import (
    VirtualNetwork,
    AddressSpace,
    Subnet,
    PublicIPAddress,
    NetworkSecurityGroup,
    SecurityRule,
    NetworkInterface,
    NetworkInterfaceIPConfiguration,
    IPAllocationMethod,
    IPVersion,
    SecurityRuleProtocol,
    SecurityRuleAccess,
    SecurityRuleDirection,
)

from azure.mgmt.compute.models import (
    SecurityEncryptionTypes,
    VMDiskSecurityProfile,
    DiskCreateOptionTypes,
    VirtualMachine,
    HardwareProfile,
    StorageProfile,
    OSDisk,
    NetworkProfile,
    SecurityProfile,
    NetworkInterfaceReference,
    ImageReference,
    ManagedDiskParameters,
    StorageAccountType,
    SecurityTypes,
    UefiSettings,
    CachingTypes,
)

from azure.mgmt.resource.resources.models import ResourceGroup

import logging
import sys
import argparse
import os
import json
import base64
from pathlib import Path


logging.basicConfig(
    format="{asctime} - {levelname} - {message}",
    style="{",
    datefmt="%Y-%m-%d %H:%M",
    level=logging.INFO,
)

logging.getLogger("azure").setLevel(logging.WARNING)


from pydantic import BaseModel
from typing import List


class AttestationBackend(str):
    TRUSTED_LAUNCH = "AzureTrustedLaunchVM"
    CONFIDENTIAL_VM = "AzureConfidentialVM"


class ClusterNode(BaseModel):
    name: str
    address: str
    vm_id: str


class ClusterConfiguration(BaseModel):
    servers: List[ClusterNode]
    agents: List[ClusterNode]


def create_virtual_machine(
    compute_client: ComputeManagementClient,
    network_client: NetworkManagementClient,
    resource_group_name: str,
    location: str,
    vm_name: str,
    vm_type: str,
    vm_security_type: SecurityTypes,
    community_gallery_image_id: str,
    opened_ports: list[tuple[int, SecurityRuleProtocol]],
    virtual_network: VirtualNetwork,
    user_data: str,
):

    nic_name = f"{vm_name}VMNic"
    public_ip_name = f"{vm_name}PublicIP"
    nsg_name = f"{vm_name}NSG"
    ipconfig_name = f"ipconfig{vm_name}"

    logging.info(f"Creating Public IP: {public_ip_name}")
    public_ip = network_client.public_ip_addresses.begin_create_or_update(
        resource_group_name,
        public_ip_name,
        PublicIPAddress(
            location=location,
            public_ip_allocation_method=IPAllocationMethod.STATIC,
            public_ip_address_version=IPVersion.I_PV4,
        ),
    ).result()

    logging.info(
        f"Created public ip address {public_ip.id}, VM will be reachable at {public_ip.ip_address}",
    )

    rules = []
    for i, opened_port in enumerate(opened_ports):
        (port_num, protocol) = opened_port
        rule = SecurityRule(
            name=f"allow-{port_num}",
            protocol=protocol,
            source_port_range="*",
            destination_port_range=str(port_num),
            source_address_prefix="*",
            destination_address_prefix="*",
            access=SecurityRuleAccess.ALLOW,
            priority=1000 + (10 * i),
            direction=SecurityRuleDirection.INBOUND,
        )
        rules.append(rule)

    logging.info(f"Creating NSG: {nsg_name}")
    nsg = network_client.network_security_groups.begin_create_or_update(
        resource_group_name,
        nsg_name,
        NetworkSecurityGroup(location=location, security_rules=rules),
    ).result()

    logging.info(f"Created NSG: {nsg.id}")

    logging.info(f"Creating NIC: {nic_name}")
    if not virtual_network.subnets or len(virtual_network.subnets) == 0:
        logging.error(
            "No subnets found in the virtual network",
        )
        sys.exit(1)

    subnet = virtual_network.subnets[0]
    ip_config = NetworkInterfaceIPConfiguration(
        name=ipconfig_name,
        subnet=subnet,
        public_ip_address=public_ip,
        private_ip_allocation_method=IPAllocationMethod.DYNAMIC,
    )
    network_interface = NetworkInterface(
        location=location, network_security_group=nsg, ip_configurations=[ip_config]
    )

    nic = network_client.network_interfaces.begin_create_or_update(
        resource_group_name=resource_group_name,
        network_interface_name=nic_name,
        parameters=network_interface,
    ).result()

    logging.info(f"Created NIC: {nic.id}")

    # 4. Create Virtual Machine
    network_profile = NetworkProfile(
        network_interfaces=[NetworkInterfaceReference(id=nic.id, primary=True)]
    )
    security_profile = SecurityProfile(
        security_type=vm_security_type,
        uefi_settings=UefiSettings(secure_boot_enabled=False, v_tpm_enabled=True),
    )

    managed_disk = ManagedDiskParameters(
        storage_account_type=StorageAccountType.PREMIUM_LRS
    )

    if vm_security_type == SecurityTypes.CONFIDENTIAL_VM:
        disk_security_profile = VMDiskSecurityProfile(
            security_encryption_type=SecurityEncryptionTypes.VM_GUEST_STATE_ONLY
        )
        managed_disk = ManagedDiskParameters(
            storage_account_type=StorageAccountType.PREMIUM_LRS,
            security_profile=disk_security_profile,
        )

    os_disk = OSDisk(
        name=f"{vm_name}_os_disk",
        caching=CachingTypes.READ_WRITE,
        create_option=DiskCreateOptionTypes.FROM_IMAGE,
        managed_disk=managed_disk,
    )
    storage_profile = StorageProfile(
        image_reference=ImageReference(
            community_gallery_image_id=community_gallery_image_id
        ),
        os_disk=os_disk,
    )
    vm_parameters = VirtualMachine(
        location=location,
        hardware_profile=HardwareProfile(vm_size=vm_type),
        storage_profile=storage_profile,
        network_profile=network_profile,
        security_profile=security_profile,
        user_data=user_data,
    )

    logging.info(
        f"Creating Virtual Machine: {vm_name}. This operation will take around 4 minutes."
    )
    vm = compute_client.virtual_machines.begin_create_or_update(
        resource_group_name, vm_name, vm_parameters
    ).result()
    logging.info(f"Created Virtual Machine: {vm.id}")
    logging.info(f"{vm_name} reachable at {public_ip.ip_address}.")

    return (public_ip.ip_address, vm.vm_id)


def main(
    vm_type: str,
    vm_security_type: SecurityTypes,
    num_control_plane: int,
    num_agents: int,
    operator_pem_cert_path: str,
    resource_group_name: str,
    location: str,
    community_gallery_image_id: str,
    output_path: Path,
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

    logging.info(f"Validating location '{location}'")
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

    logging.info(f"Successfully validated location")

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

    network_client = NetworkManagementClient(credential, subscription_id)

    subnet_name = "my-subnet"
    virtual_network_name = "my-virtualnetwork"

    logging.info(f"Creating virtual network {virtual_network_name}")

    # Define the subnet
    subnet = Subnet(name=subnet_name, address_prefix="10.0.0.0/24")

    # Define the Virtual Network parameters
    parameters = VirtualNetwork(
        location=location,
        address_space=AddressSpace(address_prefixes=["10.0.0.0/16"]),
        subnets=[subnet],
    )

    virtual_network = network_client.virtual_networks.begin_create_or_update(
        resource_group_name, virtual_network_name, parameters
    ).result()

    logging.info(f"Created virtual network {virtual_network.id}")

    operator_pem_cert = open(operator_pem_cert_path).read()
    user_data_str = json.dumps(
        {
            "creator_certificate_pem": operator_pem_cert,
            "attestation_backend": (
                "AzureConfidentialVM"
                if vm_security_type == SecurityTypes.CONFIDENTIAL_VM
                else "AzureTrustedLaunchVM"
            ),
        }
    )
    user_data = base64.b64encode(user_data_str.encode()).decode()

    # Port for the provisioning protocol
    custom_protocol_port: tuple[int, SecurityRuleProtocol] = (
        3443,
        SecurityRuleProtocol.TCP,
    )

    # Port for the ACME protocol, open only on one of the master nodes
    acme_protocol_port: tuple[int, SecurityRuleProtocol] = (
        80,
        SecurityRuleProtocol.TCP,
    )

    # Port on which the deployed application is listening on
    application_port: tuple[int, SecurityRuleProtocol] = (
        443,
        SecurityRuleProtocol.TCP,
    )

    # https://docs.k3s.io/installation/requirements?#inbound-rules-for-k3s-nodes
    control_plane_ports = [
        (6443, SecurityRuleProtocol.TCP),  # K3s supervisor and Kubernetes API Server
        (10250, SecurityRuleProtocol.TCP),  # Kubelet metrics
        (
            51820,
            SecurityRuleProtocol.UDP,
        ),  # Required only for Flannel Wireguard with IPv4
        (
            51821,
            SecurityRuleProtocol.UDP,
        ),  # Required only for Flannel Wireguard with IPv6
    ]

    master_ports = control_plane_ports.copy()
    master_ports.append(custom_protocol_port)
    master_ports.append(acme_protocol_port)
    master_ports.append(application_port)

    server_ports = control_plane_ports.copy()
    server_ports.append(custom_protocol_port)

    agent_ports = [custom_protocol_port]

    compute_client = ComputeManagementClient(credential, subscription_id)

    logging.info(
        f"Making sure the vm type requested is valid for the current subscription id and location"
    )

    skus = compute_client.resource_skus.list(filter=location)
    found = False
    for sku in skus:
        if sku.resource_type == "virtualMachines" and sku.name == vm_type:
            found = True

    if not found:
        logging.error(
            f"The VM Size requested does not exist: {vm_type}",
        )
        sys.exit(1)

    vms: ClusterConfiguration = ClusterConfiguration(servers=[], agents=[])
    master_vm_name = "master-vm"

    (master_ip_address, vm_id) = create_virtual_machine(
        compute_client=compute_client,
        network_client=network_client,
        resource_group_name=resource_group_name,
        location=location,
        vm_type=vm_type,
        vm_security_type=vm_security_type,
        vm_name=master_vm_name,
        community_gallery_image_id=community_gallery_image_id,
        opened_ports=master_ports,
        virtual_network=virtual_network,
        user_data=user_data,
    )
    master = ClusterNode(
        name=master_vm_name, address=str(master_ip_address), vm_id=str(vm_id)
    )
    vms.servers.append(master)
    # The master was already spawned
    num_control_plane = num_control_plane - 1

    # Spawn the other control plane
    for idx in range(0, num_control_plane):
        master_vm_name = f"master{idx}-vm"
        (master_ip_address, vm_id) = create_virtual_machine(
            compute_client=compute_client,
            network_client=network_client,
            resource_group_name=resource_group_name,
            location=location,
            vm_type=vm_type,
            vm_security_type=vm_security_type,
            vm_name=master_vm_name,
            community_gallery_image_id=community_gallery_image_id,
            opened_ports=server_ports,
            virtual_network=virtual_network,
            user_data=user_data,
        )

        master = ClusterNode(
            name=master_vm_name, address=str(master_ip_address), vm_id=str(vm_id)
        )
        vms.servers.append(master)

    for idx in range(0, num_agents):
        agent_vm_name = f"agent{idx}-vm"
        (agent_ip_address, vm_id) = create_virtual_machine(
            compute_client=compute_client,
            network_client=network_client,
            resource_group_name=resource_group_name,
            location=location,
            vm_type=vm_type,
            vm_security_type=vm_security_type,
            vm_name=agent_vm_name,
            community_gallery_image_id=community_gallery_image_id,
            opened_ports=agent_ports,  # type: ignore
            virtual_network=virtual_network,
            user_data=user_data,
        )
        agent = ClusterNode(
            name=agent_vm_name, address=str(agent_ip_address), vm_id=str(vm_id)
        )
        vms.agents.append(agent)

    with open(output_path, "w") as outfile:
        outfile.write(vms.model_dump_json())


def cli():
    parser = argparse.ArgumentParser(
        description="Command line tool to create virtual machines on Azure Cloud."
    )

    parser.add_argument(
        "--vm-type",
        help="Type of vm to use for control plane and agent nodes (such as `Standard_NC24ads_A100_v4`).",
        type=str,
        required=True,
    )

    parser.add_argument(
        "--vm-security-type",
        help="Type of security to use: AzureTrustedLaunchVM or AzureConfidentialVM.",
        type=AttestationBackend,
        required=True,
    )

    parser.add_argument(
        "--num-control-plane-nodes",
        type=int,
        required=True,
        help="Number of control plane nodes. Must be greater or equal to 1.",
    )

    parser.add_argument(
        "--num-agent-nodes",
        type=int,
        required=False,
        help="Number of agent nodes. Not required.",
        default=0,
    )

    parser.add_argument(
        "--operator-pem-cert-path",
        type=str,
        required=True,
        help="Path to the file containing the operator PEM encoded certificate.",
    )

    parser.add_argument(
        "--resource-group-name",
        type=str,
        required=True,
        help="Resource group where the resources will be created.",
    )

    parser.add_argument(
        "--location",
        type=str,
        required=True,
        help="Location where the resources will be created.",
    )

    parser.add_argument(
        "--community-gallery-image-id",
        type=str,
        required=True,
        help="Image Resource ID to provision the vms with.",
    )

    parser.add_argument(
        "--output-path",
        type=str,
        required=False,
        help="Path where the output will be saved (e.g. ./cluster.json)",
        default=Path("./cluster.json"),
    )

    args = parser.parse_args()

    if not os.path.isfile(args.operator_pem_cert_path):
        parser.error(
            f"The path to the operator pem certificate is not valid: {args.operator_pem_cert_path} \nMake sure the path is exists and that it points to a file."
        )

    if args.num_control_plane_nodes < 1:
        parser.error("--num-control-plane-nodes must be at least 1.")

    if args.vm_security_type == AttestationBackend.TRUSTED_LAUNCH:
        vm_security_type = SecurityTypes.TRUSTED_LAUNCH
    elif args.vm_security_type == AttestationBackend.CONFIDENTIAL_VM:
        vm_security_type = SecurityTypes.CONFIDENTIAL_VM
    else:
        parser.error(
            f"The vm_security_type is not valid: {args.vm_security_type}. Allowed values are AzureTrustedLaunchVM and AzureConfidentialVM"
        )

    main(
        resource_group_name=args.resource_group_name,
        location=args.location,
        vm_type=args.vm_type,
        vm_security_type=vm_security_type,
        num_control_plane=args.num_control_plane_nodes,
        num_agents=args.num_agent_nodes,
        operator_pem_cert_path=args.operator_pem_cert_path,
        community_gallery_image_id=args.community_gallery_image_id,
        output_path=args.output_path,
    )


if __name__ == "__main__":
    cli()
