"""
GCP VM CLI - Provision GCP Shielded VMs with attestation support.

This script orchestrates the deployment of:
1. A GCP Confidential VM (CVM) running the notarizer service (from image.raw)
2. GCP Shielded VMs running the multinode provisioning server

The notarizer on the CVM endorses the Shielded VMs' attestation keys,
allowing them to be verified through the CVM's trusted certificate chain.
"""

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests
from pydantic import BaseModel

logging.basicConfig(
    format="{asctime} - {levelname} - {message}",
    style="{",
    datefmt="%Y-%m-%d %H:%M",
    level=logging.INFO,
)

IMAGE_PROJECT = "fluorite-os"

# Paths relative to the repository root
REPO_ROOT = Path(__file__).parent.parent.parent
DEFAULT_NOTARIZER_IMAGE_PATH = REPO_ROOT / "gcp-shielded-vm-notarizer" / "disk.raw"
DEFAULT_SHIELDED_VM_IMAGE_PATH = REPO_ROOT / "fluorite-os" / "cloud-vtpm" / "disk.raw"

# ============================================================================
# Network Port Configuration
# ============================================================================

# Port for the provisioning protocol
CUSTOM_PROTOCOL_PORT = (3443, "tcp")

# Port for the ACME protocol, open only on one of the master nodes
ACME_PROTOCOL_PORT = (80, "tcp")

# Port on which the deployed application is listening on
APPLICATION_PORT = (443, "tcp")

# https://docs.k3s.io/installation/requirements?#inbound-rules-for-k3s-nodes
CONTROL_PLANE_PORTS = [
    (6443, "tcp"),   # K3s supervisor and Kubernetes API Server
    (10250, "tcp"),  # Kubelet metrics
    (51820, "udp"),  # Required only for Flannel Wireguard with IPv4
    (51821, "udp"),  # Required only for Flannel Wireguard with IPv6
]

# Master ports: control plane + custom protocol + ACME + application
MASTER_PORTS = CONTROL_PLANE_PORTS.copy()
MASTER_PORTS.append(CUSTOM_PROTOCOL_PORT)
MASTER_PORTS.append(ACME_PROTOCOL_PORT)
MASTER_PORTS.append(APPLICATION_PORT)

# Server ports: control plane + custom protocol
SERVER_PORTS = CONTROL_PLANE_PORTS.copy()
SERVER_PORTS.append(CUSTOM_PROTOCOL_PORT)

# Agent ports: only custom protocol
AGENT_PORTS = [CUSTOM_PROTOCOL_PORT]

# Network tags for each role (base names, label suffix added at runtime if specified)
TAG_NOTARIZER_BASE = "fluorite-gcp-shielded-vm-notarizer"
TAG_MASTER_BASE = "fluorite-master-node"
TAG_SERVER_BASE = "fluorite-k3s-server-node"
TAG_AGENT_BASE = "fluorite-k3s-agent-node"


class ClusterNode(BaseModel):
    name: str
    address: str
    vm_id: Optional[str] = None


class ClusterConfiguration(BaseModel):
    servers: list[ClusterNode]
    agents: list[ClusterNode]


@dataclass
class GCPConfig:
    """GCP configuration for VM creation."""

    project: str
    zone: str
    network: str
    subnet: str
    machine_type_notarizer: str = "n2d-standard-2"
    machine_type: str = "n2-standard-8"
    label: Optional[str] = None  # Optional label to apply to all resources

    def with_label_suffix(self, name: str) -> str:
        """Add label suffix to a resource name if label is defined."""
        if self.label:
            return f"{name}-{self.label}"
        return name

    def get_tag_notarizer(self) -> str:
        """Get network tag for notarizer with label suffix if defined."""
        return self.with_label_suffix(TAG_NOTARIZER_BASE)

    def get_tag_master(self) -> str:
        """Get network tag for master nodes with label suffix if defined."""
        return self.with_label_suffix(TAG_MASTER_BASE)

    def get_tag_server(self) -> str:
        """Get network tag for server nodes with label suffix if defined."""
        return self.with_label_suffix(TAG_SERVER_BASE)

    def get_tag_agent(self) -> str:
        """Get network tag for agent nodes with label suffix if defined."""
        return self.with_label_suffix(TAG_AGENT_BASE)


def run_command(
    args: list[str],
    check: bool = True,
    capture_output: bool = False,
    cwd: Optional[Path] = None,
) -> subprocess.CompletedProcess:
    """Run a shell command."""
    logging.debug(f"Running: {' '.join(args)}")
    result = subprocess.run(
        args, check=check, capture_output=capture_output, text=True, cwd=cwd
    )
    return result


def run_gcloud(
    args: list[str], check: bool = True, capture_output: bool = False
) -> subprocess.CompletedProcess:
    """Run a gcloud command."""
    return run_command(["gcloud"] + args, check=check, capture_output=capture_output)


def run_gsutil(
    args: list[str], check: bool = True, capture_output: bool = False
) -> subprocess.CompletedProcess:
    """Run a gsutil command."""
    return run_command(["gsutil"] + args, check=check, capture_output=capture_output)


def create_firewall_rules(config: GCPConfig):
    """
    Create GCP firewall rules for the fluorite cluster.

    Creates rules for:
    - Notarizer CVM (HTTPS only)
    - Master nodes (control plane + provisioning + ACME + application)
    - Server nodes (control plane + provisioning)
    - Agent nodes (provisioning only)

    If a label is specified, it is appended to rule names and target tags to avoid conflicts.
    """

    def create_rule(
        name: str,
        ports: list[tuple[int, str]],
        target_tags: list[str],
        source_ranges: list[str] = None,
    ):
        """Create a single firewall rule if it doesn't exist."""
        # Add label suffix to rule name if label is defined
        full_name = config.with_label_suffix(f"fluorite-{name}")

        # Check if rule already exists
        result = run_gcloud(
            ["compute", "firewall-rules", "describe", full_name, f"--project={config.project}"],
            check=False,
            capture_output=True,
        )
        if result.returncode == 0:
            logging.info(f"Firewall rule {full_name} already exists")
            return

        # Build allow rules as protocol:port for each port
        allow_entries = [f"{proto}:{port}" for port, proto in ports]

        if not allow_entries:
            logging.warning(f"No ports to open for rule {full_name}")
            return

        gcloud_args = [
            "compute", "firewall-rules", "create", full_name,
            f"--project={config.project}",
            f"--network={config.network}",
            f"--target-tags={','.join(target_tags)}",
            f"--allow={','.join(allow_entries)}",
            "--direction=INGRESS",
        ]

        if source_ranges:
            gcloud_args.append(f"--source-ranges={','.join(source_ranges)}")

        # Note: Firewall rules don't support labels, but the label is embedded in the name
        # for cleanup by name pattern filtering

        logging.info(f"Creating firewall rule: {full_name}")
        run_gcloud(gcloud_args)

    # Notarizer CVM: HTTPS only (port 443)
    create_rule(
        name="notarizer",
        ports=[(443, "tcp")],
        target_tags=[config.get_tag_notarizer()],
        source_ranges=["0.0.0.0/0"],
    )

    # Master nodes: all master ports
    create_rule(
        name="master",
        ports=MASTER_PORTS,
        target_tags=[config.get_tag_master()],
        source_ranges=["0.0.0.0/0"],
    )

    # Server nodes: control plane + provisioning
    create_rule(
        name="server",
        ports=SERVER_PORTS,
        target_tags=[config.get_tag_server()],
        source_ranges=["0.0.0.0/0"],
    )

    # Agent nodes: provisioning only
    create_rule(
        name="agent",
        ports=AGENT_PORTS,
        target_tags=[config.get_tag_agent()],
        source_ranges=["0.0.0.0/0"],
    )

    logging.info("Firewall rules created/verified")


def upload_image_to_gcs(
    image_path: Path,
    bucket: str,
    image_hash: str,
    image_prefix: str = "gcp-notarizer-os",
) -> str:
    """
    Upload the raw disk image to GCS.

    GCP requires the image to be named disk.raw and compressed as disk.raw.tar.gz.

    Returns the GCS URI of the uploaded tar.gz file.
    """
    logging.info(f"Compressing and uploading {image_prefix} image to GCS...")

    blob_name = f"{image_prefix}-{image_hash}.tar.gz"
    gcs_uri = f"gs://{bucket}/{blob_name}"

    # Check if already uploaded
    result = run_gsutil(["ls", gcs_uri], check=False, capture_output=True)
    if result.returncode == 0:
        logging.info(f"Image already exists in GCS: {gcs_uri}")
        return gcs_uri

    # GCP requires the image to be named disk.raw inside the tar.gz
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        disk_raw_path = temp_path / "disk.raw"
        tar_gz_path = temp_path / "disk.raw.tar.gz"

        # Copy the image as disk.raw
        logging.info(f"Copying {image_path} to {disk_raw_path}")
        shutil.copy2(image_path, disk_raw_path)

        # Create tar.gz archive
        logging.info(f"Creating tar.gz archive: {tar_gz_path}")
        run_command(["tar", "-czf", str(tar_gz_path), "-C", str(temp_path), "disk.raw"])

        # Upload to GCS
        logging.info(f"Uploading to {gcs_uri}")
        run_gsutil(["cp", str(tar_gz_path), gcs_uri])

    logging.info(f"Upload complete: {gcs_uri}")
    return gcs_uri


def create_gcp_image(
    gcs_uri: str,
    config: GCPConfig,
    image_hash: str,
    image_prefix: str = "gcp-notarizer-os",
    guest_os_features: str = "UEFI_COMPATIBLE,SEV_CAPABLE,SEV_SNP_CAPABLE,VIRTIO_SCSI_MULTIQUEUE",
) -> str:
    """
    Create a GCP Compute Engine image from the GCS raw disk.

    Returns the image name.
    """
    image_name = f"{image_prefix}-{image_hash}"

    logging.info(f"Creating GCP Compute Engine image: {image_name}...")

    # Check if image already exists
    result = run_gcloud(
        [
            "compute",
            "images",
            "describe",
            image_name,
            f"--project={config.project}",
        ],
        check=False,
        capture_output=True,
    )

    if result.returncode == 0:
        logging.info(f"Image {image_name} already exists, skipping creation")
        return image_name

    logging.info(f"Creating image: {image_name}")

    gcloud_args = [
        "compute",
        "images",
        "create",
        image_name,
        f"--project={config.project}",
        f"--source-uri={gcs_uri}",
        f"--guest-os-features={guest_os_features}",
    ]

    # Add label if specified
    if config.label:
        gcloud_args.append(f"--labels={config.label}=true")

    run_gcloud(gcloud_args)

    logging.info(f"Image created: {image_name}")
    return image_name


def get_image_hash(image_path: Path) -> str:
    """
    Generate a hash for the image based on its measurement file or modification time.
    """
    # Check for os-measurement.json in same directory
    measurement_path = image_path.parent / "os-measurement.json"
    if measurement_path.exists():
        with open(measurement_path, "r") as f:
            measurement_data = json.load(f)
        pcr4 = measurement_data.get("fluoriteos_pcr4", "")
        if pcr4:
            return pcr4[:12]
    # If PCR hash not found, warn and use fallback.
    logging.warning(
        f"PCR4 measurement not found in {measurement_path}, falling back to file modification time for hash."
    )
    # Fallback: use file modification time as hash
    mtime = int(image_path.stat().st_mtime)
    return hashlib.md5(str(mtime).encode()).hexdigest()[:12]


def create_notarizer_cvm(
    name: str,
    config: GCPConfig,
    image_name: str,
    creator_cert_pem: str,
) -> str:
    """
    Create a GCP Confidential VM (AMD SEV) for the notarizer using the pre-built image.

    Returns the external IP address of the VM.
    """
    logging.info(f"Creating Confidential VM for notarizer: {name}")

    import shlex

    # For multiline PEM values, use a file and reference it using --metadata-from-file
    # Write the creator certificate PEM to a temp file
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w") as tf:
        tf.write(creator_cert_pem)
        creator_cert_file = tf.name
        tf.flush()

        gcloud_args = [
            "compute", "instances", "create", name,
            f"--project={config.project}",
            f"--zone={config.zone}",
            "--confidential-compute-type=SEV",
            f"--machine-type={config.machine_type_notarizer}",
            "--min-cpu-platform=AMD Milan",
            "--maintenance-policy=MIGRATE",
            f"--image={image_name}",
            f"--image-project={IMAGE_PROJECT}",
            f"--subnet={config.subnet}",
            "--scopes=compute-ro",
            f"--metadata-from-file=creator-certificate={creator_cert_file}",
            f"--tags={config.get_tag_notarizer()}",
        ]

        # Add label if specified
        if config.label:
            gcloud_args.append(f"--labels={config.label}=true")

        run_gcloud(gcloud_args)
    
    # Get the external IP
    result = run_gcloud([
        "compute", "instances", "describe", name,
        f"--project={config.project}",
        f"--zone={config.zone}",
        "--format=json",
    ], capture_output=True)
    
    instance_info = json.loads(result.stdout)

    # Try to get external IP, fall back to internal IP
    try:
        external_ip = instance_info["networkInterfaces"][0]["accessConfigs"][0]["natIP"]
    except (KeyError, IndexError):
        external_ip = instance_info["networkInterfaces"][0]["networkIP"]
        logging.warning(f"No external IP found, using internal IP: {external_ip}")

    logging.info(f"Notarizer CVM {name} created with IP: {external_ip}")
    return external_ip


def wait_for_notarizer_service(
    ip: str,
    port: int,
    operator_cert_path: str,
    operator_key_path: str,
    timeout: int = 300,
) -> bool:
    """Wait for the notarizer service to become available."""
    logging.info(f"Waiting for notarizer service at https://{ip}:{port}...")

    url = f"https://{ip}:{port}/health"
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            response = requests.get(
                url,
                cert=(operator_cert_path, operator_key_path),
                verify=False,
                timeout=5,
            )
            if response.status_code == 200:
                logging.info(f"Notarizer service is up: {response.text}")
                return True
        except requests.exceptions.RequestException as e:
            logging.debug(f"Service not ready: {e}")

        time.sleep(10)

    logging.error(f"Notarizer service not available after {timeout} seconds")
    return False


def create_shielded_vm(
    name: str,
    config: GCPConfig,
    creator_cert_pem: str,
    role: str,
    image: Optional[str] = None,
    max_retries: int = 3,
) -> tuple[str, str]:
    """
    Create a GCP Shielded VM (Trusted Launch).

    Args:
        name: VM instance name
        config: GCP configuration
        creator_cert_pem: Operator certificate PEM
        role: Node role - "master", "server", or "agent"
        image: GCP image name to use
        max_retries: Maximum number of retry attempts for zone resource exhaustion errors

    Returns a tuple of (external_ip, instance_self_link).
    """
    logging.info(f"Creating Shielded VM: {name} (role: {role})")

    # Determine network tag based on role (with label suffix if defined)
    if role == "master":
        network_tag = config.get_tag_master()
    elif role == "server":
        network_tag = config.get_tag_server()
    elif role == "agent":
        network_tag = config.get_tag_agent()
    else:
        raise ValueError(f"Unknown role: {role}")

    # Prepare userdata for the provisioning server
    userdata = {
        "creator_certificate_pem": creator_cert_pem,
        "attestation_backend": "GcpShieldedVM",
    }

    # Write userdata to a temp file to avoid shell escaping issues with gcloud
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(userdata, f)
        userdata_file = f.name

    try:
        gcloud_args = [
            "compute", "instances", "create", name,
            f"--project={config.project}",
            f"--zone={config.zone}",
            f"--machine-type={config.machine_type}",
            "--shielded-vtpm",
            "--maintenance-policy=TERMINATE",
            f"--image={image}",
            f"--image-project={IMAGE_PROJECT}",
            f"--subnet={config.subnet}",
            f"--metadata-from-file=user-data={userdata_file}",
            f"--tags={network_tag}",
        ]

        # Add label if specified
        if config.label:
            gcloud_args.append(f"--labels={config.label}=true")

        # Retry loop for zone resource exhaustion errors
        last_exception = None
        for attempt in range(1, max_retries + 1):
            try:
                result = run_gcloud(gcloud_args, check=False, capture_output=True)
                if result.returncode == 0:
                    break  # Success

                # Check if this is a zone resource exhaustion error
                error_output = result.stderr or ""
                if "ZONE_RESOURCE_POOL_EXHAUSTED" in error_output:
                    logging.warning(
                        f"Zone resource exhausted on attempt {attempt}/{max_retries} for {name}. "
                    )
                    last_exception = subprocess.CalledProcessError(
                        result.returncode, gcloud_args, result.stdout, result.stderr
                    )
                    if attempt == max_retries:
                        logging.error(
                            f"Failed to create VM {name} after {max_retries} attempts due to zone resource exhaustion"
                        )
                        raise last_exception
                else:
                    # Non-retryable error, raise immediately
                    raise subprocess.CalledProcessError(
                        result.returncode, gcloud_args, result.stdout, result.stderr
                    )
            except subprocess.CalledProcessError:
                raise
    finally:
        os.unlink(userdata_file)

    # Get the external IP and self link
    result = run_gcloud([
        "compute", "instances", "describe", name,
        f"--project={config.project}",
        f"--zone={config.zone}",
        "--format=json",
    ], capture_output=True)
    
    instance_info = json.loads(result.stdout)
    external_ip = instance_info["networkInterfaces"][0]["accessConfigs"][0]["natIP"]
    self_link = instance_info["selfLink"]

    logging.info(f"Shielded VM {name} created with IP: {external_ip}")
    return external_ip, self_link


def get_notarizer_endorsement(
    notarizer_ip: str,
    notarizer_port: int,
    target_project: str,
    target_zone: str,
    target_instance: str,
    operator_cert_path: str,
    operator_key_path: str,
) -> dict:
    """
    Get a notarizer endorsement for a Shielded VM.

    Uses TLS client certificate authentication.
    """
    logging.info(f"Getting notarizer endorsement for {target_instance}")

    url = f"https://{notarizer_ip}:{notarizer_port}/notarize"

    request_body = {
        "project": target_project,
        "zone": target_zone,
        "instance": target_instance,
    }

    response = requests.post(
        url,
        json=request_body,
        cert=(operator_cert_path, operator_key_path),
        verify=False,  # Self-signed server cert
        timeout=30,
    )

    response.raise_for_status()
    endorsement = response.json()

    logging.info(f"Got notarizer endorsement for {target_instance}")
    return endorsement


def update_vm_metadata(
    name: str,
    config: GCPConfig,
    notarizer_endorsement: dict,
    creator_cert_pem: str,
):
    """Update VM metadata with notarizer endorsement and userdata."""
    logging.info(f"Updating metadata for {name}")

    # Create the complete userdata including the endorsement
    userdata = {
        "creator_certificate_pem": creator_cert_pem,
        "attestation_backend": "GcpShieldedVM",
        "notarizer_endorsement": notarizer_endorsement,
    }

    # Write userdata to a temp file to avoid shell escaping issues with gcloud
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(userdata, f)
        userdata_file = f.name

    try:
        run_gcloud([
            "compute", "instances", "add-metadata", name,
            f"--project={config.project}",
            f"--zone={config.zone}",
            f"--metadata-from-file=user-data={userdata_file}",
        ])
    finally:
        os.unlink(userdata_file)

    logging.info(f"Metadata updated for {name}")


def delete_vm(name: str, config: GCPConfig):
    """Delete a GCP VM instance."""
    logging.info(f"Deleting VM: {name}")
    run_gcloud(
        [
            "compute",
            "instances",
            "delete",
            name,
            f"--project={config.project}",
            f"--zone={config.zone}",
            "--quiet",
        ],
        check=False,
    )


def main(
    project: str,
    zone: str,
    network: str,
    subnet: str,
    operator_cert_path: str,
    operator_key_path: str,
    num_servers: int,
    num_agents: int,
    notarizer_instance_name: str = "notarizer-cvm",
    bucket: Optional[str] = None,
    notarizer_image: Optional[str] = None,
    notarizer_image_path: Optional[Path] = None,
    fluorite_os_image: Optional[str] = None,
    fluorite_os_image_path: Optional[Path] = None,
    skip_cleanup: bool = False,
    output_path: Path = Path("./cluster.json"),
    machine_type_notarizer: str = "n2d-standard-2",
    machine_type: str = "n2-standard-8",
    label: Optional[str] = None,
):
    """Main orchestration function."""

    # Load the operator certificate
    with open(operator_cert_path, "r") as f:
        creator_cert_pem = f.read()

    config = GCPConfig(
        project=project,
        zone=zone,
        network=network,
        subnet=subnet,
        machine_type_notarizer=machine_type_notarizer,
        machine_type=machine_type,
        label=label,
    )

    notarizer_image_name = ""
    shielded_vm_image_name: Optional[str] = None
    cvm_ip = ""
    all_vms: list[tuple[str, str, str, str]] = []  # (name, ip, zone, role)
    endorsements: dict[str, dict] = {}  # instance_name -> endorsement

    # Pre-compute notarizer VM name with label suffix
    notarizer_vm_name = config.with_label_suffix(notarizer_instance_name)

    try:
        # Step 0: Create firewall rules
        logging.info("=" * 60)
        logging.info("Step 0: Creating/verifying firewall rules")
        logging.info("=" * 60)

        create_firewall_rules(config)

        # Step 1: Prepare notarizer OS image
        logging.info("=" * 60)
        logging.info("Step 1: Preparing notarizer OS image")
        logging.info("=" * 60)

        if notarizer_image:
            # Use existing GCP image directly
            notarizer_image_name = notarizer_image
            logging.info(f"Using existing notarizer image: {notarizer_image_name}")
        else:
            # Upload from local path and create image
            notarizer_hash = get_image_hash(notarizer_image_path)
            gcs_uri = upload_image_to_gcs(
                notarizer_image_path,
                config,
                notarizer_hash,
                image_prefix="gcp-notarizer-os",
            )
            notarizer_image_name = create_gcp_image(
                gcs_uri,
                config,
                notarizer_hash,
                image_prefix="gcp-notarizer-os",
                guest_os_features="UEFI_COMPATIBLE,SEV_CAPABLE,SEV_SNP_CAPABLE,SEV_LIVE_MIGRATABLE_V2,VIRTIO_SCSI_MULTIQUEUE",
            )

        # Step 1b: Prepare Shielded VM OS image
        logging.info("=" * 60)
        logging.info("Step 1b: Preparing Fluorite OS image")
        logging.info("=" * 60)

        if fluorite_os_image:
            # Use existing GCP image directly
            shielded_vm_image_name = fluorite_os_image
            logging.info(f"Using existing Fluorite OS image: {shielded_vm_image_name}")
        else:
            # Upload from local path and create image
            shielded_hash = get_image_hash(fluorite_os_image_path)
            shielded_gcs_uri = upload_image_to_gcs(
                fluorite_os_image_path,
                config,
                shielded_hash,
                image_prefix="gcp-shielded-vm",
            )
            shielded_vm_image_name = create_gcp_image(
                shielded_gcs_uri,
                config,
                shielded_hash,
                image_prefix="gcp-shielded-vm",
                guest_os_features="UEFI_COMPATIBLE",
            )

        # Step 2: Create the CVM for the notarizer
        logging.info("=" * 60)
        logging.info("Step 2: Creating Confidential VM for notarizer")
        logging.info("=" * 60)

        cvm_ip = create_notarizer_cvm(
            notarizer_vm_name, config, notarizer_image_name, creator_cert_pem
        )

        # Step 3: Wait for notarizer service to be ready
        logging.info("=" * 60)
        logging.info("Step 3: Waiting for notarizer service")
        logging.info("=" * 60)

        if not wait_for_notarizer_service(
            cvm_ip, 443, operator_cert_path, operator_key_path
        ):
            raise RuntimeError("Notarizer service did not become available")

        # Step 4: Create Shielded VMs
        logging.info("=" * 60)
        logging.info("Step 4: Creating Shielded VMs")
        logging.info("=" * 60)

        cluster = ClusterConfiguration(servers=[], agents=[])

        # Create server nodes (first one is the master)
        for i in range(num_servers):
            if i == 0:
                base_name = "master-server"
                role = "master"
            else:
                base_name = f"server-{i}"
                role = "server"
            # Add label suffix to VM name if label is defined
            name = config.with_label_suffix(base_name)
            ip, _ = create_shielded_vm(
                name, config, creator_cert_pem, role=role, image=shielded_vm_image_name
            )
            all_vms.append((name, ip, zone, role))
            cluster.servers.append(ClusterNode(name=name, address=ip))

        # Create agent nodes
        for i in range(num_agents):
            base_name = f"agent-{i}"
            # Add label suffix to VM name if label is defined
            name = config.with_label_suffix(base_name)
            ip, _ = create_shielded_vm(
                name,
                config,
                creator_cert_pem,
                role="agent",
                image=shielded_vm_image_name,
            )
            all_vms.append((name, ip, zone, "agent"))
            cluster.agents.append(ClusterNode(name=name, address=ip))

        # Step 5: Get endorsements for ALL shielded VMs
        logging.info("=" * 60)
        logging.info("Step 5: Getting notarizer endorsements for all Shielded VMs")
        logging.info("=" * 60)

        for name, ip, vm_zone, role in all_vms:
            endorsement = get_notarizer_endorsement(
                notarizer_ip=cvm_ip,
                notarizer_port=443,
                target_project=project,
                target_zone=vm_zone,
                target_instance=name,
                operator_cert_path=operator_cert_path,
                operator_key_path=operator_key_path,
            )
            endorsements[name] = endorsement

        logging.info(f"Successfully obtained endorsements for {len(endorsements)} VMs")

        # Step 6: Now that all endorsements are obtained, clean up notarizer CVM
        logging.info("=" * 60)
        logging.info("Step 6: Cleaning up notarizer CVM")
        logging.info("=" * 60)

        if not skip_cleanup:
            delete_vm(notarizer_vm_name, config)
            logging.info(f"Notarizer CVM {notarizer_vm_name} deleted")
        else:
            logging.info(
                f"Skipping cleanup (--skip-cleanup). Notarizer running at https://{cvm_ip}"
            )

        # Step 7: Update metadata on all Shielded VMs with their endorsements
        logging.info("=" * 60)
        logging.info("Step 7: Updating Shielded VM metadata with endorsements")
        logging.info("=" * 60)

        for name, ip, vm_zone, role in all_vms:
            update_vm_metadata(name, config, endorsements[name], creator_cert_pem)

        # Save cluster configuration
        with open(output_path, "w") as f:
            f.write(cluster.model_dump_json(indent=2))

        # Save endorsements for reference
        with open("endorsements.json", "w") as f:
            json.dump(endorsements, f, indent=2)

        logging.info("=" * 60)
        logging.info("Deployment complete!")
        logging.info(f"Cluster configuration saved to {output_path}")
        logging.info(f"Endorsements saved to endorsements.json")
        logging.info("=" * 60)

        return 0

    except Exception as e:
        logging.exception(f"Error during deployment: {e}")

        # Cleanup on error
        if not skip_cleanup:
            logging.info("Cleaning up resources due to error...")
            if cvm_ip:
                delete_vm(notarizer_vm_name, config)
            for name, _, _, _ in all_vms:
                delete_vm(name, config)

        return 1


def cli():
    parser = argparse.ArgumentParser(
        description="GCP VM CLI - Provision GCP Shielded VMs with attestation support"
    )

    parser.add_argument(
        "--project",
        type=str,
        required=True,
        help="GCP project ID",
    )

    parser.add_argument(
        "--zone",
        type=str,
        default="default",
        help="GCP zone (e.g., europe-west10-a)",
    )

    parser.add_argument(
        "--network",
        type=str,
        default="default",
        help="GCP network name (default: default)",
    )

    parser.add_argument(
        "--subnet",
        type=str,
        default="default",
        help="GCP subnet name (default: default)",
    )

    parser.add_argument(
        "--bucket",
        type=str,
        required=False,
        help="GCS bucket for storing images (required when using --*-image-path options)",
    )

    parser.add_argument(
        "--operator-cert-path",
        type=str,
        required=True,
        help="Path to the operator PEM certificate",
    )

    parser.add_argument(
        "--operator-key-path",
        type=str,
        required=True,
        help="Path to the operator private key",
    )

    # Notarizer image options (mutually exclusive)
    notarizer_group = parser.add_mutually_exclusive_group(required=True)
    notarizer_group.add_argument(
        "--notarizer-image",
        type=str,
        help="Name of an existing GCP notarizer image (e.g., gcp-notarizer-os-0-0-0-testing-20260122184816)",
    )
    notarizer_group.add_argument(
        "--notarizer-image-path",
        type=str,
        help=f"Path to the notarizer disk.raw file to upload (default: {DEFAULT_NOTARIZER_IMAGE_PATH})",
    )

    # Fluorite OS image options (mutually exclusive)
    fluorite_os_group = parser.add_mutually_exclusive_group(required=True)
    fluorite_os_group.add_argument(
        "--fluorite-os-image",
        type=str,
        help="Name of an existing GCP Fluorite OS image (e.g., fluorite-os-0-0-0-testing-20260122184816)",
    )
    fluorite_os_group.add_argument(
        "--fluorite-os-image-path",
        type=str,
        help=f"Path to the Fluorite OS disk.raw file to upload (default: {DEFAULT_SHIELDED_VM_IMAGE_PATH})",
    )

    parser.add_argument(
        "--num-servers",
        type=int,
        default=1,
        help="Number of server nodes (default: 1)",
    )

    parser.add_argument(
        "--num-agents",
        type=int,
        default=0,
        help="Number of agent nodes (default: 0)",
    )

    parser.add_argument(
        "--notarizer-instance-name",
        type=str,
        default="notarizer",
        help="Name for the CVM running the notarizer (default: notarizer)",
    )

    parser.add_argument(
        "--skip-cleanup",
        action="store_true",
        help="Skip cleanup of notarizer CVM (leave it running)",
    )

    parser.add_argument(
        "--output-path",
        type=str,
        required=False,
        help="Path where the output will be saved (e.g. ./cluster.json)",
        default=Path("./cluster.json"),
    )

    parser.add_argument(
        "--machine-type-notarizer",
        type=str,
        required=False,
        help="GCP machine type for the notarizer CVM (default: n2d-standard-2)",
        default="n2d-standard-2",
    )

    parser.add_argument(
        "--machine-type",
        type=str,
        required=False,
        help="GCP machine type for the Shielded VMs (default: n2-standard-8)",
        default="n2-standard-8",
    )

    parser.add_argument(
        "--label",
        type=str,
        required=False,
        help="Optional label to apply to all GCP resources (VMs, images, firewall rules). "
        "Use this to easily identify and clean up resources later. "
        "Example: --label=my-deployment-123",
        default=None,
    )

    args = parser.parse_args()

    # Validate paths
    if not os.path.isfile(args.operator_cert_path):
        parser.error(f"Operator certificate not found: {args.operator_cert_path}")

    if not os.path.isfile(args.operator_key_path):
        parser.error(f"Operator private key not found: {args.operator_key_path}")

    # Validate bucket is provided when using path options
    if (args.notarizer_image_path or args.fluorite_os_image_path) and not args.bucket:
        parser.error(
            "--bucket is required when using --notarizer-image-path or --fluorite-os-image-path"
        )

    # Validate notarizer image path if provided
    notarizer_image_path: Optional[Path] = None
    if args.notarizer_image_path:
        notarizer_image_path = Path(args.notarizer_image_path)
        if not notarizer_image_path.is_file():
            parser.error(
                f"Notarizer image not found: {notarizer_image_path}. Run 'earthly +gcp-notarizer-os' first."
            )

    # Validate Fluorite OS image path if provided
    fluorite_os_image_path: Optional[Path] = None
    if args.fluorite_os_image_path:
        fluorite_os_image_path = Path(args.fluorite_os_image_path)
        if not fluorite_os_image_path.is_file():
            parser.error(f"Fluorite OS image not found: {fluorite_os_image_path}")

    if args.num_servers < 1:
        parser.error("--num-servers must be at least 1")

    # Validate label format if provided
    # GCP labels must: start with lowercase letter, contain only lowercase letters, numbers, underscores, dashes
    # and be at most 63 characters
    if args.label:
        import re

        if not re.match(r"^[a-z][a-z0-9_-]{0,62}$", args.label):
            parser.error(
                "--label must start with a lowercase letter and contain only lowercase letters, "
                "numbers, underscores, and dashes (max 63 characters)"
            )

    sys.exit(
        main(
            project=args.project,
            zone=args.zone,
            network=args.network,
            subnet=args.subnet,
            operator_cert_path=args.operator_cert_path,
            operator_key_path=args.operator_key_path,
            num_servers=args.num_servers,
            num_agents=args.num_agents,
            notarizer_instance_name=args.notarizer_instance_name,
            bucket=args.bucket,
            notarizer_image=args.notarizer_image,
            notarizer_image_path=notarizer_image_path,
            fluorite_os_image=args.fluorite_os_image,
            fluorite_os_image_path=fluorite_os_image_path,
            skip_cleanup=args.skip_cleanup,
            output_path=args.output_path,
            machine_type_notarizer=args.machine_type_notarizer,
            machine_type=args.machine_type,
            label=args.label,
        )
    )


if __name__ == "__main__":
    cli()
