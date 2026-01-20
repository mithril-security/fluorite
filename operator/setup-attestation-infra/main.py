from azure.identity import AzureCliCredential
from azure.core.exceptions import ClientAuthenticationError
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient

from azure.mgmt.resource.resources.models import ResourceGroup
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
)

from azure.mgmt.cdn import CdnManagementClient
from azure.mgmt.cdn.models import (
    Profile,
    Sku as SkuCdn,
    AFDOriginGroup,
    LoadBalancingSettingsParameters,
    HealthProbeParameters,
    HealthProbeRequestType,
    AFDOrigin,
    EnabledState,
    AFDEndpoint,
    Route,
    LinkToDefaultDomain,
    ForwardingProtocol,
    ActivatedResourceReference,
    ResourceReference,
    AFDDomain,
    AFDDomainHttpsParameters,
    AfdCertificateType,
    AfdMinimumTlsVersion,
)
from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.dns.models import RecordSet, TxtRecord, CnameRecord, RecordType


from utils import run_command
import sys
import argparse
import random
import string
import logging
from urllib.parse import urlparse
import requests
import json

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


def main(
    resource_group_name: str,
    location: str,
    dns_zone_name: str,
    storage_account_name: str,
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
        kind=Kind("StorageV2"),
        allow_blob_public_access=False,
        minimum_tls_version=MinimumTlsVersion.TLS1_2,
        encryption=encryption,
        enable_https_traffic_only=True,
    )

    storage_account = storage_client.storage_accounts.begin_create(
        resource_group_name=resource_group_name,
        account_name=storage_account_name,
        parameters=storage_account_parameters,
    ).result()
    logging.info(f"Success. Created Storage Account {storage_account_name}")
    logging.info(f"Activating Static Website on Storage Account {storage_account_name}")
    run_command(
        [
            "az",
            "storage",
            "blob",
            "service-properties",
            "update",
            "--account-name",
            storage_account_name,
            "--static-website",
        ]
    )
    logging.info(
        f"Successfully activated Static Website on Storage Account {storage_account_name}"
    )

    cdn_client = CdnManagementClient(credential, subscription_id)

    front_door_name = f"frontdoor{generate_random_string(5)}"
    logging.info(f"Creating Front Door {front_door_name} ")
    profile = Profile(location="global", sku=SkuCdn(name="Standard_AzureFrontDoor"))

    front_door_create = cdn_client.profiles.begin_create(
        resource_group_name=resource_group_name,
        profile_name=front_door_name,
        profile=profile,
    ).result()

    logging.info(f"Successfully created Front Door {front_door_name}")

    origin_group_name = f"origingroup{generate_random_string(5)}"
    logging.info(
        f"Creating Origin Group {origin_group_name} for Front Door {front_door_name} "
    )
    # Default settings
    load_balancing_setting_parameter = LoadBalancingSettingsParameters(
        sample_size=4,
        successful_samples_required=3,
        additional_latency_in_milliseconds=50,
    )
    health_probe_settings = HealthProbeParameters(
        probe_path="/",
        probe_protocol="Http",
        probe_request_type=HealthProbeRequestType.HEAD,
        probe_interval_in_seconds=100,
    )

    afd_origin_group = AFDOriginGroup(
        load_balancing_settings=load_balancing_setting_parameter,
        health_probe_settings=health_probe_settings,
    )

    origin_group = cdn_client.afd_origin_groups.begin_create(
        resource_group_name=resource_group_name,
        profile_name=front_door_name,
        origin_group_name=origin_group_name,
        origin_group=afd_origin_group,
    ).result()

    logging.info(
        f"Successfully created Origin Group {origin_group_name} for Front Door {front_door_name} "
    )

    origin_name = f"origingroup{generate_random_string(5)}"
    logging.info(
        f"Creating Origin {origin_name} on Front Door {front_door_name} for Origin Group {origin_group_name} "
    )

    if (
        not storage_account.primary_endpoints
        or not storage_account.primary_endpoints.web
    ):
        logging.error("Could not get web endpoint for Storage Account. Exiting")
        sys.exit(1)

    host_name = urlparse(storage_account.primary_endpoints.web).netloc

    afd_origin = AFDOrigin(
        host_name=host_name,
        origin_host_header=host_name,
        priority=1,
        weight=1000,
        enabled_state=EnabledState.ENABLED,
        http_port=80,
        https_port=443,
        enforce_certificate_name_check=True,
    )

    origin_create = cdn_client.afd_origins.begin_create(
        resource_group_name=resource_group_name,
        profile_name=front_door_name,
        origin_group_name=origin_group_name,
        origin_name=origin_name,
        origin=afd_origin,
    ).result()

    logging.info(
        f"Successfully created Origin {origin_name} on Front Door {front_door_name} for Origin Group {origin_group_name} "
    )

    endpoint_name = f"endpoint{generate_random_string(5)}"
    logging.info(f"Creating Endpoint {endpoint_name} on Front Door {front_door_name}")

    afd_endpoint = AFDEndpoint(enabled_state=EnabledState.ENABLED, location="global")

    endpoint = cdn_client.afd_endpoints.begin_create(
        resource_group_name=resource_group_name,
        profile_name=front_door_name,
        endpoint_name=endpoint_name,
        endpoint=afd_endpoint,
    ).result()

    logging.info(
        f"Successfully created Endpoint {endpoint_name} on Front Door {front_door_name}"
    )

    custom_domain_host = f"proofs"

    if not endpoint.host_name:
        logging.error("Could host_name of the Endpoint. Exiting")
        sys.exit(1)

    logging.info(
        f"Creating DNS Record in the Zone {custom_domain_host} for Host {endpoint.host_name}"
    )

    dns_client = DnsManagementClient(credential, subscription_id)

    cname_data = CnameRecord(cname=f"{endpoint.host_name}")

    record_set_params = RecordSet(ttl=3600, cname_record=cname_data)

    logging.info(
        f"Creating CNAME record in Azure Zone {dns_zone_name} with Name {custom_domain_host} pointing to {endpoint.host_name}"
    )

    result = dns_client.record_sets.create_or_update(
        resource_group_name=resource_group_name,
        zone_name=dns_zone_name,
        relative_record_set_name=custom_domain_host,
        record_type=RecordType.CNAME,
        parameters=record_set_params,
    )

    logging.info(
        f"Successfully created DNS Record in the Zone {custom_domain_host} for Host {endpoint.host_name}"
    )

    custom_domain_name = "mycustomdomain"

    logging.info(
        f"Creating Custom Frontend Domain {custom_domain_host}.{dns_zone_name} for Front Door {front_door_name}"
    )

    domain_params = AFDDomainHttpsParameters(
        certificate_type=AfdCertificateType.MANAGED_CERTIFICATE,
        minimum_tls_version=AfdMinimumTlsVersion.TLS12,
    )
    host_name = f"{custom_domain_host}.{dns_zone_name}"
    afd_domain = AFDDomain(host_name=host_name, tls_settings=domain_params)
    custom_domain = cdn_client.afd_custom_domains.begin_create(
        resource_group_name=resource_group_name,
        profile_name=front_door_name,
        custom_domain_name=custom_domain_name,
        custom_domain=afd_domain,
    ).result()

    logging.info(
        f"Successfully created custom Frontend Domain {custom_domain_host} for Front Door {front_door_name}"
    )

    if (
        not custom_domain.validation_properties
        or not custom_domain.validation_properties.validation_token
    ):
        logging.error("Could not get validation token of the custom domain. Exiting")
        sys.exit(1)

    validation_token: str = custom_domain.validation_properties.validation_token

    record_name = f"_dnsauth.{custom_domain_host}"

    logging.info(
        f"Adding dnsatuh TXT record with name {record_name} to DNS Zone {custom_domain_host}"
    )

    txt_record_data = TxtRecord(value=[f"{validation_token}"])

    record_set_params = RecordSet(ttl=3600, txt_records=[txt_record_data])

    result = dns_client.record_sets.create_or_update(
        resource_group_name=resource_group_name,
        zone_name=dns_zone_name,
        relative_record_set_name=record_name,
        record_type=RecordType.TXT,
        parameters=record_set_params,
    )
    
    logging.info(
        f"Successfully added validation TXT record with name {record_name} to DNS Zone {custom_domain_host}"
    )

    route_name = f"route{generate_random_string(5)}"

    logging.info(
        f"Creating Route {route_name} for Endpoint {endpoint_name} on Front Door {front_door_name} with Custom Domain"
    )

    route = Route(
        origin_group=ResourceReference(id=origin_group.id),
        https_redirect="Enabled",
        supported_protocols=["Http", "Https"],
        patterns_to_match=["/*"],
        link_to_default_domain=LinkToDefaultDomain.DISABLED,
        custom_domains=[ActivatedResourceReference(id=custom_domain.id)],
        forwarding_protocol=ForwardingProtocol.MATCH_REQUEST,
    )

    route = cdn_client.routes.begin_create(
        resource_group_name=resource_group_name,
        profile_name=front_door_name,
        endpoint_name=endpoint_name,
        route_name=route_name,
        route=route,
    ).result()
    logging.info(
        f"Successfully created Route {route_name} for Endpoint {endpoint_name} on Front Door {front_door_name} with Custom Domain"
    )

    logging.info("Done. DNS propagation may take between 5-30 minutes.")
    logging.info(
        f"You should be able to reach the Storage Account at the link https://{host_name}/"
    )
    return {
        "storage_url": f"https://{host_name}/",
        "attestation_storage_account_name": storage_account_name,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Script for deploying the infrastructure needed for the Attestation Transparency Service"
    )

    parser.add_argument(
        "--resource-group-name", help="Resource Group Name", type=str, required=True
    )
    parser.add_argument(
        "--location",
        help="Location of the Resource Group and where the Resources will be created",
        type=str,
        required=True,
    )
    parser.add_argument(
        "--zone-name",
        help="domain to operate on eg. demo.mithrilsecurity.io",
        type=str,
        required=True,
    )

    parser.add_argument(
        "--storage_account_name",
        help="storage account name eg. attestsgkou",
        type=str,
        required=True,
    )

    args = parser.parse_args()

    result = main(
        resource_group_name=args.resource_group_name,
        location=args.location,
        dns_zone_name=args.zone_name,
        storage_account_name=args.storage_account_name,
    )

    with open("attestation-infra.json", "w") as f:
        json.dump(result, f)
