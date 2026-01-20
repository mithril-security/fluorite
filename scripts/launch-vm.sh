#!/bin/bash

# Inspired by 
# - https://linuxcommand.org/lc3_wss0120.php
# - https://github.com/AMDESE/AMDSEV/blob/69a015ff07263bc83627df2508e9c7063ea8035f/launch-qemu.sh
# - https://docs.nvidia.com/cc-deployment-guide-snp.pdf

#### DEFAULTS 

CPU_MODEL="EPYC-Genoa-v1"
SMP=16
MEM=150
NETWORK="user,id=vmnic,hostfwd=tcp::3443-:3443,hostfwd=tcp::6443-:6443,hostfwd=tcp::443-:443,hostfwd=tcp::80-:80"

# earthly +ovmf
OVMF_PATH="./coconut-svsm/OVMF.fd"

# earthly +igvm
COCONUT_IGVM_PATH="./coconut-svsm/coconut-qemu.igvm"

# earthly +qemu
QEMU_BIN_PATH="./qemu/usr/local/bin/qemu-system-x86_64"
QEMU_LIB_DIR_PATH="./igvminst/usr/lib/x86_64-linux-gnu/"

SEED_IMG_PATH="./seed.img"

DISK_PATH="./fluorite-os/baremetal-amd-sev/disk.raw"

CONFIDENTIAL_VM=
VIRTUALIZATION_TYPE=
GPU_SETUP=

usage()
{
    cat << EOF
sudo $0 [options]
--mem MEM                                         guest memory size in GB (default $MEM)."
--smp NCPUS                                       number of virtual cpus (default $SMP)."
--cpu CPU_MODEL                                   QEMU CPU model/type to use (default $CPU_MODEL). 
                                                  See: https://man.archlinux.org/man/extra/qemu-common/qemu-cpu-models.7.en#x86-64_ABI_compatibility_levels."
--qemu-bin-path                                   Path to the qemu binary (default: $QEMU_BIN_PATH).
--qemu-lib-dir-path                               Path to the qemu library directory (default: $QEMU_LIB_DIR_PATH).
--ovmf_path                                       Path to the OVMF firmware file (default: $OVMF_PATH).
--coconut_igvm_path                               Path to the Coconut IGVM file (default: $COCONUT_IGVM_PATH).
--seed_img_path                                   Path to the seed image file used by cloud-init (default: $SEED_IMG_PATH).
--disk_path                                       Path to the OS disk image file (default: $DISK_PATH).
--confidential                                    Enable this flag to start a confidential guest VM (CVM).
--virtualization_type                             Specify the virtualization type (e.g., 'sev', 'sev-es' or 'sev-snp').
--network                                         The user network option (default: $NETWORK).
--gpu_setup                                       Enable vfio-pci kernel module, and set gpu in CC mode.
-h    | --help                                    Brings up this menu
EOF

}

#### PRELIMIARY CHECK
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run with root privileges (e.g., using 'sudo')."
  exit 1
fi

while [ "$1" != "" ]; do
    case $1 in
        --mem                   ) shift 
                                MEM=$1
                                ;;
        
        --cpu                   ) shift 
                                CPU=$1
                                ;;
        
        --smp                 ) shift 
                                SMP=$1
                                ;;

        --qemu-bin-path )       shift
                                QEMU_BIN_PATH=$1
                                ;;
        
        --qemu-lib-dir-path )   shift
                                QEMU_LIB_DIR_PATH=$1
                                ;;
        --ovmf_path )           shift
                                OVMF_PATH=$1
                                ;;
        --coconut_igvm_path )   shift
                                COCONUT_IGVM_PATH=$1
                                ;;
        --seed_img_path )       shift
                                SEED_IMG_PATH=$1
                                ;;
        
        --disk_path )           shift
                                DISK_PATH=$1
                                ;;

        --confidential )        CONFIDENTIAL_VM=1
                                ;;
        
        --virtualization_type ) shift
                                VIRTUALIZATION_TYPE=$1
                                ;;
        
        --network )             shift
                                NETWORK=$1
                                ;;

        --gpu_setup )           GPU_SETUP=1
                                ;; 

        -h | --help )           usage
                                exit
                                ;;
        * )                     usage
                                exit 1
    esac
    shift
done

# https://github.com/AMDESE/AMDSEV/blob/69a015ff07263bc83627df2508e9c7063ea8035f/launch-qemu.sh#L72
get_cbitpos() {
	modprobe cpuid
	#
	# Get C-bit position directly from the hardware
	#   Reads of /dev/cpu/x/cpuid have to be 16 bytes in size
	#     and the seek position represents the CPUID function
	#     to read.
	#   The skip parameter of DD skips ibs-sized blocks, so
	#     can't directly go to 0x8000001f function (since it
	#     is not a multiple of 16). So just start at 0x80000000
	#     function and read 32 functions to get to 0x8000001f
	#   To get to EBX, which contains the C-bit position, skip
	#     the first 4 bytes (EAX) and then convert 4 bytes.
	#

	EBX=$(dd if=/dev/cpu/0/cpuid ibs=16 count=32 skip=134217728 | tail -c 16 | od -An -t u4 -j 4 -N 4 | sed -re 's|^ *||')
	CBITPOS=$((EBX & 0x3f))
}

if [ "$CONFIDENTIAL_VM" = "1" ]; then
  case "$VIRTUALIZATION_TYPE" in
        sev | sev-es | sev-snp)
            SEV_MODE="$VIRTUALIZATION_TYPE"
            USE_CC=true
            get_cbitpos
            ;;
        *)
            echo "Error: unsupported SEV mode '$VIRTUALIZATION_TYPE'."
            usage
            exit 1
            ;;
    esac
fi

NVIDIA_GPU=$(lspci -d 10de: | awk '/NVIDIA/{print $1}')
NVIDIA_PASSTHROUGH=$(lspci -n -s $NVIDIA_GPU | awk -F: '{print $4}' | awk '{print $1}')

echo "NVIDIA_PASSTHROUGH: $NVIDIA_PASSTHROUGH"
echo "NVIDIA_GPU: $NVIDIA_GPU"

if [ "$GPU_SETUP" = "1" ]; then
    echo -n "10de $NVIDIA_PASSTHROUGH" > /sys/bus/pci/drivers/vfio_pci/unbind
    # Load vfio-pci kernel module
    modprobe vfio-pci
    echo -n "10de $NVIDIA_PASSTHROUGH" > /sys/bus/pci/drivers/vfio-pci/new_id

    echo "Setting cc mode to on"
    if [ ! -d "./fluorite-cli/tools/gpu-admin-tools" ]; then
        echo "Getting the gpu-admin-tools from https://github.com/NVIDIA/gpu-admin-tools.git"
        git clone --branch v2025.10.20 https://github.com/NVIDIA/gpu-admin-tools.git ./fluorite-cli/tools/gpu-admin-tools
    fi 
    cd ./fluorite-cli/tools/gpu-admin-tools
    python3 ./nvidia_gpu_tools.py --devices gpus --set-cc-mode=on --reset-after-cc-mode-switch
    cd -
    
fi





rm /tmp/disk.qcow
qemu-img convert -f raw -O qcow2 $DISK_PATH /tmp/disk.qcow
DISK_PATH=/tmp/disk.qcow

echo "Launching VM ..."

LD_LIBRARY_PATH=$QEMU_LIB_DIR_PATH $QEMU_BIN_PATH \
    -bios $OVMF_PATH \
    -object igvm-cfg,id=igvm0,file=$COCONUT_IGVM_PATH \
    -nographic \
    ${USE_CC:+ -machine confidential-guest-support=sev0,vmport=off,igvm-cfg=igvm0 } \
    ${USE_CC:+$([ "$SEV_MODE" = sev ] &&
        echo " -object sev-guest,id=sev0,cbitpos=${CBITPOS},reduced-phys-bits=1,policy=0x1")} \
    ${USE_CC:+$([ "$SEV_MODE" = sev-es ] &&
        echo " -object sev-guest,id=sev0,cbitpos=${CBITPOS},reduced-phys-bits=1,policy=0x5")} \
    ${USE_CC:+$([ "$SEV_MODE" = sev-snp ] &&
        echo " -object sev-snp-guest,id=sev0,cbitpos=${CBITPOS},reduced-phys-bits=1,policy=0x30000")} \
    -vga none \
    -enable-kvm \
    -no-reboot \
    -cpu $CPU_MODEL \
    -machine q35 -smp $SMP -m ${MEM}G,slots=2,maxmem=512G \
    -drive file=$DISK_PATH,if=none,id=disk0,format=qcow2 \
    -drive if=virtio,format=raw,file=${SEED_IMG_PATH} \
    -device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true,romfile= \
    -device scsi-hd,drive=disk0 \
    -netdev $NETWORK \
    -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= \
    -device pcie-root-port,id=pci.1,bus=pcie.0 \
    -object iommufd,id=iommufd0 \
    -device vfio-pci,host=${NVIDIA_GPU},bus=pci.1,romfile='',iommufd=iommufd0
