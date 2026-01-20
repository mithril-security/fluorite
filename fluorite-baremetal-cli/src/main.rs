use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod artifact_manager;
mod guest;
mod host;
mod utils;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    cmd: Commands,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug, Clone)]
enum Commands {
    GetArtifacts {
        /// The version to get e.g. 0.1.0
        #[clap(long)]
        release_version: String,

        /// Path to the provenance file for verification
        #[clap(long)]
        provenance_path: Option<PathBuf>,

        // Skip provencance SLSA verification
        #[clap(long, default_value_t = false)]
        insecure_skip_verify: bool,
    },
    SetupHost,
    LaunchGuest {
        /// Path to the OVMF firmware file
        /// earthly +ovmf
        #[clap(long, default_value = "./scripts/launch-vm.sh")]
        launch_vm_script_path: PathBuf,

        /// Path to the OVMF firmware file
        /// earthly +ovmf
        #[clap(long, default_value = "./coconut-svsm/OVMF.fd")]
        ovmf_path: PathBuf,

        /// Path to the Coconut IGVM file
        /// earthly +igvm
        #[clap(long, default_value = "./coconut-svsm/coconut-qemu.igvm")]
        coconut_igvm_path: PathBuf,

        /// Path to the qemu binary
        /// earthly +qemu
        #[clap(long, default_value = "./qemu/usr/local/bin/qemu-system-x86_64")]
        qemu_bin_path: PathBuf,

        /// Path to the qemu library directory
        /// earthly +qemu
        #[clap(long, default_value = "./igvminst/usr/lib/x86_64-linux-gnu/")]
        qemu_lib_dir_path: PathBuf,

        /// Path to the OS disk image file
        /// earthly --strict -P +fluorite-os --nvidia_driver=true --snp_bare_metal=true --output_dir=fluorite-os/baremetal-amd-sev/
        #[clap(long, default_value = "./fluorite-os/baremetal-amd-sev/disk.raw")]
        disk_path: PathBuf,

        /// Path to the user-data file used by cloud-init.
        #[clap(long, default_value = "./user-data.yaml")]
        user_data_path: PathBuf,

        /// Path to the meta-data file used by cloud-init.
        #[clap(long, default_value = "./meta-data.yaml")]
        meta_data_path: PathBuf,

        /// Enable this flag to start a confidential guest VM (CVM).
        #[clap(long)]
        confidential: bool,

        /// Specify the virtualization type (e.g., 'sev', 'sev-es' or 'sev-snp').
        #[clap(long)]
        virtualization_type: Option<String>,

        /// guest memory size in GB.
        #[clap(long, default_value = "150")]
        mem: u32,

        /// number of virtual cpus.
        #[clap(long, default_value = "16")]
        smp: u32,

        /// QEMU CPU model/type to use. See: https://man.archlinux.org/man/extra/qemu-common/qemu-cpu-models.7.en#x86-64_ABI_compatibility_levels.
        #[clap(long, default_value = "EPYC-Genoa-v1")]
        cpu: String,

        /// The user network option.
        #[clap(
            long,
            default_value = "user,id=vmnic,hostfwd=tcp::3443-:3443,hostfwd=tcp::6443-:6443,hostfwd=tcp::443-:443,hostfwd=tcp::80-:80"
        )]
        network: String,

        /// If the script itself should handle setting up the gpu.
        #[clap(long, default_value = "false")]
        gpu_setup: bool,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // axum logs rejections from built-in extractors with the `axum::rejection`
                // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                "fluorite_baremetal=debug" // azure_core=debug
                    .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    match args.cmd {
        Commands::GetArtifacts {
            release_version,
            provenance_path,
            insecure_skip_verify,
        } => {
            artifact_manager::get_artifacts(release_version, provenance_path, insecure_skip_verify)
        }
        Commands::SetupHost => host::setup_host(),
        Commands::LaunchGuest {
            launch_vm_script_path,
            user_data_path,
            meta_data_path,
            ovmf_path,
            coconut_igvm_path,
            qemu_bin_path,
            qemu_lib_dir_path,
            disk_path,
            confidential,
            virtualization_type,
            mem,
            smp,
            cpu,
            network,
            gpu_setup,
        } => guest::launch_guest(
            launch_vm_script_path,
            user_data_path,
            meta_data_path,
            ovmf_path,
            coconut_igvm_path,
            qemu_bin_path,
            qemu_lib_dir_path,
            disk_path,
            confidential,
            virtualization_type,
            mem,
            smp,
            cpu,
            network,
            gpu_setup,
        ),
    }
}
