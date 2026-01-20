VERSION 0.8

mkosi-builder:
    FROM ubuntu:25.04

    ENV DEBIAN_FRONTEND=noninteractive


    RUN apt-get update && apt-get install --assume-yes --no-install-recommends \
        cryptsetup libcryptsetup-dev \
        git \
        meson \
        gcc \
        gperf \
        libcap-dev \
        libmount-dev \
        libssl-dev \
        python3-jinja2 \
        pkg-config \
        ca-certificates \
        btrfs-progs \
        bubblewrap \
        debian-archive-keyring \
        dnf \
        e2fsprogs \
        erofs-utils \
        mtools \
        ovmf \
        python3-pefile \
        python3-pyelftools \
        qemu-system-x86 \
        squashfs-tools \
        swtpm \
        xfsprogs \
        zypper \
        curl \
        libtss2-dev \
        tpm2-tools \
        systemd-boot \
        systemd-container \
        systemd-repart \
        systemd-ukify \
        pesign \
        dosfstools \
        cpio \
        zstd \
        kmod \
        reprepro \
        jq
    
    COPY +uv/uv /usr/local/bin/uv
    RUN uv tool install git+https://github.com/systemd/mkosi.git@v25.3

    SAVE IMAGE debian-systemd

rust-builder: 
    FROM ubuntu:25.04

    # Set environment variables to avoid prompts during package installation
    ENV DEBIAN_FRONTEND=noninteractive

    # Update the package list and install necessary dependencies
    RUN apt-get update && \
        apt-get install -y \
        build-essential \
        git \
        curl \
        pkg-config \
        libtss2-dev \
        tpm2-tools \
        autoconf \
        autoconf-archive \
        automake \
        m4 \
        libtool \
        gcc \
        libssl-dev \
        libxml2-dev \
        libxmlsec1-dev \
        libclang-dev \
        libxmlsec1-openssl
    
    # Hardcode toolchain to nightly-2026-01-26-x86_64-unknown-linux-gnu
    RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain nightly-2026-01-26-x86_64-unknown-linux-gnu --profile minimal

    # Add Rust binaries to PATH
    ENV PATH="/root/.cargo/bin:$PATH"

    RUN rustup toolchain install nightly-2026-01-26-x86_64-unknown-linux-gnu --profile minimal


multinode-provisioning-server:
    FROM +rust-builder

    CACHE /root/.cargo/registry
    CACHE /root/.cargo/git

    CACHE ./multinode-provisioning/server/target

    COPY ./libraries/provisioning-structs/ ./libraries/provisioning-structs/
    COPY ./libraries/attestation/ ./libraries/attestation/

    COPY ./multinode-provisioning/server/.cargo ./multinode-provisioning/server/.cargo
    COPY ./multinode-provisioning/server/rust-toolchain.toml ./multinode-provisioning/server/rust-toolchain.toml
    COPY ./multinode-provisioning/server/Cargo.toml ./multinode-provisioning/server/Cargo.toml
    COPY ./multinode-provisioning/server/Cargo.lock ./multinode-provisioning/server/Cargo.lock
    COPY ./multinode-provisioning/server/src/ ./multinode-provisioning/server/src/
    WORKDIR ./multinode-provisioning/server

    RUN cargo build --release --locked

    RUN cp ./target/release/provisioning /provisioning
    
    SAVE ARTIFACT /provisioning AS LOCAL ./multinode-provisioning/server/target/release/provisioning
    SAVE ARTIFACT /provisioning

uv: 
    FROM ubuntu:25.04
    ENV DEBIAN_FRONTEND=noninteractive

    RUN apt-get update && apt-get install --assume-yes --no-install-recommends curl ca-certificates

    RUN curl -sL https://github.com/astral-sh/uv/releases/download/0.9.25/uv-x86_64-unknown-linux-gnu.tar.gz -o uv-x86_64-unknown-linux-gnu.tar.gz && \
        echo "fa1f4abfe101d43e820342210c3c6854028703770f81e95b119ed1e65ec81b35  uv-x86_64-unknown-linux-gnu.tar.gz" | sha256sum --check && \
        tar xvf uv-x86_64-unknown-linux-gnu.tar.gz -C /usr/local/bin --strip-components=1
    SAVE ARTIFACT /usr/local/bin/uv

setup-rootfs:
    FROM ubuntu:25.04

    ENV DEBIAN_FRONTEND=noninteractive

    RUN apt-get update && apt-get install --assume-yes --no-install-recommends curl ca-certificates git    
    
    RUN K3S_VERSION=v1.35.0+k3s1 && \
        curl -sL "https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION}/k3s" -o ./k3s && \
        echo "959c9310a6ab893958d1c95bc5d7609de9d7884630c8832180f059369b6dc331 ./k3s" | sha256sum --check && \
        chmod +x ./k3s && \
        curl -sL "https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION}/k3s-airgap-images-amd64.tar.zst" -o ./k3s-airgap-images-amd64.tar.zst && \
        echo "2e3d6d14bbbeb8c16f1849cca8da48887c5a7ddceb1cc2bf60be63e4fa8c63f3  ./k3s-airgap-images-amd64.tar.zst" | sha256sum --check

    
    RUN ZARF_VERSION=v0.69.0 && \
        curl -sL "https://github.com/zarf-dev/zarf/releases/download/${ZARF_VERSION}/zarf_${ZARF_VERSION}_Linux_amd64" -o ./zarf && \
        echo "aaf5240df5adc7a039eb223628b0b3927ef0657f0ec0048edbfe653e5eb5da12  ./zarf" | sha256sum --check && \
        chmod +x ./zarf && \
        curl -sL "https://github.com/zarf-dev/zarf/releases/download/${ZARF_VERSION}/zarf-init-amd64-${ZARF_VERSION}.tar.zst" -o ./zarf-init-amd64-$ZARF_VERSION.tar.zst && \
        echo "81f129dddafe08b4a00ef9fe0b19f5c2f8247658f29a9d8a0f685fe35a7989b2  ./zarf-init-amd64-$ZARF_VERSION.tar.zst" | sha256sum --check 

    COPY os-base/ os-base/
    WORKDIR os-base
    # Make sure file permissions are correct
    RUN find ./rootfs/mkosi.extra/ -type d -exec chmod 644 {} \;
    RUN find ./rootfs/mkosi.extra/ -type f -exec chmod 755 {} \;
    
    # Install k3s airgap 
    RUN mkdir -p ./rootfs/mkosi.extra/usr/local/bin ./rootfs/mkosi.extra/var/lib/rancher/k3s/agent/images/ && \
        cp ../k3s ./rootfs/mkosi.extra/usr/local/bin/k3s && \
        cp ../k3s-airgap-images-amd64.tar.zst ./rootfs/mkosi.extra/var/lib/rancher/k3s/agent/images/k3s-airgap-images-amd64.tar.zst

    # Install zarf
    RUN ZARF_VERSION=v0.69.0 && mkdir -p ./rootfs/mkosi.extra/root/.zarf-cache && \
        cp ../zarf ./rootfs/mkosi.extra/usr/local/bin/zarf && \
        cp ../zarf-init-amd64-$ZARF_VERSION.tar.zst ./rootfs/mkosi.extra/root/.zarf-cache/zarf-init-amd64-$ZARF_VERSION.tar.zst && \
        mkdir -p ./rootfs/mkosi.extra/root/.local/state

    RUN mkdir -p ./rootfs/mkosi.extra/opt/
    COPY +multinode-provisioning-server/provisioning ./rootfs/mkosi.extra/opt/provisioning

    COPY +uv/uv /usr/local/bin/uv
    RUN uv tool install render_template/
    
    ARG debug = false
    ARG debug_ssh_key = ""
    ARG nvidia_driver = false
    ARG snp_bare_metal = false

    RUN echo "debug: $debug" > config.yaml
    RUN echo "debug_ssh_key: \"$debug_ssh_key\"" >> config.yaml
    RUN echo "nvidia_driver: $nvidia_driver" >> config.yaml
    RUN echo "snp_bare_metal: $snp_bare_metal" >> config.yaml

    RUN /root/.local/bin/render_template ./config.yaml ./rootfs/mkosi.conf.j2
    RUN /root/.local/bin/render_template ./config.yaml ./rootfs/mkosi.postinst.j2
    RUN chmod +x ./rootfs/mkosi.postinst

    SAVE ARTIFACT ./rootfs

fluorite-os:
    FROM +mkosi-builder

    ARG snp_bare_metal = false

    IF [ "$snp_bare_metal" = "true" ]
        COPY +build-guest-kernel-svsm/svsm-linux ./svsm-linux
    END

    COPY +setup-rootfs/rootfs ./rootfs

    CACHE ./rootfs/mkosi.cache
    RUN --privileged /root/.local/bin/mkosi -C ./rootfs/

    # Compute the golden PCR4 for the os image and save
    COPY scripts/compute_measurements.py scripts/compute_measurements.py 
    RUN --privileged python3 scripts/compute_measurements.py ./rootfs/build/disk

    ARG output_dir = "platform/cloud-vtpm/"

    SAVE ARTIFACT os-measurement.json AS LOCAL $output_dir/os-measurement.json
    SAVE ARTIFACT ./rootfs/build/disk AS LOCAL $output_dir/disk.raw
    SAVE ARTIFACT ./rootfs/build/disk.manifest AS LOCAL $output_dir/disk.manifest


cert-manager-plugin-builder:
    FROM DOCKERFILE operator/packages/common/fluorite-approver-policy-plugin/
    SAVE IMAGE fluorite-approver-policy-plugin:latest

gpu-attestation-checker-builder:
    FROM DOCKERFILE operator/packages/zarf_ray/
    SAVE IMAGE gpu-attestation-checker:latest

zarf-builder: 
    FROM ubuntu:25.04
    ENV DEBIAN_FRONTEND=noninteractive
    RUN apt-get update && apt-get install -y curl 

    # Docker installation is required for building images with custom cert manager approver policy
    DO github.com/earthly/lib+INSTALL_DIND
    RUN ZARF_VERSION=v0.69.0 && \
        curl -sL "https://github.com/zarf-dev/zarf/releases/download/${ZARF_VERSION}/zarf_${ZARF_VERSION}_Linux_amd64" -o ./zarf && \
        echo "aaf5240df5adc7a039eb223628b0b3927ef0657f0ec0048edbfe653e5eb5da12  ./zarf" | sha256sum --check && \
        chmod +x zarf

    COPY operator/packages/common/ ./operator/packages/common
    COPY operator/packages/skeleton/ ./operator/packages/skeleton
    RUN ./zarf tools helm repo add jetstack https://charts.jetstack.io

zarf-nginx:
    FROM +zarf-builder
    CACHE /root/.zarf-cache/

    COPY ./operator/packages/zarf_nginx/ ./operator/packages/zarf_nginx
    WITH DOCKER --load +cert-manager-plugin-builder
        RUN ./zarf package create operator/packages/zarf_nginx/
    END
    SAVE ARTIFACT ./zarf-package-nginx-amd64-0.1.0.tar.zst AS LOCAL ./packages/zarf-package-nginx-amd64-0.1.0.tar.zst

zarf-ray:
    FROM +zarf-builder
    CACHE /root/.zarf-cache/

    COPY ./operator/packages/zarf_ray_tl/ ./operator/packages/zarf_ray_tl
    COPY ./operator/packages/zarf_ray/ ./operator/packages/zarf_ray
    WITH DOCKER --load fluorite-approver-policy-plugin:latest=+cert-manager-plugin-builder \
                --load gpu-attestation-checker:latest=+gpu-attestation-checker-builder
        RUN ./zarf package create operator/packages/zarf_ray/
    END
    SAVE ARTIFACT ./zarf-package-ray-amd64-0.1.0.tar.zst AS LOCAL ./packages/zarf-package-ray-amd64-0.1.0.tar.zst

zarf-ray-tl:
    FROM +zarf-builder
    CACHE /root/.zarf-cache/

    COPY ./operator/packages/zarf_ray_tl/ ./operator/packages/zarf_ray_tl
    WITH DOCKER --load fluorite-approver-policy-plugin:latest=+cert-manager-plugin-builder
        RUN ./zarf package create operator/packages/zarf_ray_tl/
    END
    SAVE ARTIFACT ./zarf-package-ray-amd64-0.1.0.tar.zst AS LOCAL ./packages/zarf-package-ray-tl-amd64-0.1.0.tar.zst

zarf-nginx-self-ca:
    FROM +zarf-builder
    CACHE /root/.zarf-cache/

    COPY ./operator/packages/zarf_nginx_self_ca/ ./operator/packages/zarf_nginx_self_ca
    RUN ./zarf package create operator/packages/zarf_nginx_self_ca/

    SAVE ARTIFACT ./zarf-package-nginx-amd64-0.1.0.tar.zst AS LOCAL ./packages/zarf-package-nginx-self-ca-amd64-0.1.0.tar.zst

fluorite-cli:
    FROM +rust-builder

    CACHE /root/.cargo/registry
    CACHE /root/.cargo/git

    CACHE ./operator/fluorite-cli/target

    COPY ./libraries/provisioning-structs/ ./libraries/provisioning-structs/
    COPY ./libraries/attested-server-verifier/ ./libraries/attested-server-verifier/ 
    COPY ./libraries/attestation/ ./libraries/attestation/

    COPY ./operator/fluorite-cli/.cargo ./operator/fluorite-cli/.cargo
    COPY ./operator/fluorite-cli/rust-toolchain.toml ./operator/fluorite-cli/rust-toolchain.toml
    COPY ./operator/fluorite-cli/Cargo.toml ./operator/fluorite-cli/Cargo.toml
    COPY ./operator/fluorite-cli/Cargo.lock ./operator/fluorite-cli/Cargo.lock
    COPY ./operator/fluorite-cli/src/ ./operator/fluorite-cli/src/
    WORKDIR ./operator/fluorite-cli/

    RUN cargo build --release --locked
    
    # Since we are caching the build binary, save artifact can't find it
    # because it's in a different volume, so copy it out of the cache

    RUN cp ./target/release/fluorite /fluorite
    
    SAVE ARTIFACT /fluorite AS LOCAL ./operator/fluorite-cli/target/release/fluorite

fluorite-baremetal-cli:
    FROM +rust-builder

    CACHE /root/.cargo/registry
    CACHE /root/.cargo/git

    CACHE ./fluorite-baremetal-cli/target
    
    COPY ./fluorite-baremetal-cli/.cargo ./fluorite-baremetal-cli/.cargo
    COPY ./fluorite-baremetal-cli/rust-toolchain.toml ./fluorite-baremetal-cli/rust-toolchain.toml
    COPY ./fluorite-baremetal-cli/Cargo.toml ./fluorite-baremetal-cli/Cargo.toml
    COPY ./fluorite-baremetal-cli/Cargo.lock ./fluorite-baremetal-cli/Cargo.lock
    COPY ./fluorite-baremetal-cli/src/ ./fluorite-baremetal-cli/src/
    WORKDIR ./fluorite-baremetal-cli/

    RUN cargo build --release --locked
    
    # Since we are caching the build binary, save artifact can't find it
    # because it's in a different volume, so copy it out of the cache

    RUN cp ./target/release/fluorite-baremetal /fluorite-baremetal
    
    SAVE ARTIFACT /fluorite-baremetal AS LOCAL ./fluorite-baremetal-cli/target/release/fluorite-baremetal

attestation-transparency-service:
    FROM +rust-builder
    
    CACHE /root/.cargo/registry
    CACHE /root/.cargo/git
    
    CACHE ./attestation-transparency-service/target

    COPY ./libraries/provisioning-structs/ ./libraries/provisioning-structs/
    COPY ./libraries/attested-server-verifier/ ./libraries/attested-server-verifier/ 
    COPY ./libraries/attestation/ ./libraries/attestation/
    COPY ./libraries/cloud-helpers/ ./libraries/cloud-helpers/

    COPY ./attestation-transparency-service/.cargo ./attestation-transparency-service/.cargo
    COPY ./attestation-transparency-service/rust-toolchain.toml ./attestation-transparency-service/rust-toolchain.toml
    COPY ./attestation-transparency-service/Cargo.toml ./attestation-transparency-service/Cargo.toml
    COPY ./attestation-transparency-service/Cargo.lock ./attestation-transparency-service/Cargo.lock
    COPY ./attestation-transparency-service/src/ ./attestation-transparency-service/src/
    WORKDIR ./attestation-transparency-service/

    RUN cargo build --release --locked
    # Since we are caching the build binary, save artifact can't find it
    # because it's in a different volume, so copy it out of the cache

    RUN cp ./target/release/attestation-transparency-service /ats
    
    SAVE ARTIFACT /ats AS LOCAL ./attestation-transparency-service/target/release/attestation-transparency-service

attestation-transparency-service-image:
    # Use a minimal base image for the final, smaller runtime image
    FROM ubuntu:25.04

    # Install necessary runtime dependencies
    RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        lsb-release \
        gnupg \
        libxml2-dev \
        libxmlsec1-dev \
        libclang-dev \
        && rm -rf /var/lib/apt/lists/*

    # Install Azure CLI
    RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

    # Set the working directory in the container
    WORKDIR /app

    # Copy the pre-built binary from the GitHub Actions runner's context
    COPY +attestation-transparency-service/ats ./attestation-transparency-service
    COPY ./measurements/ ./measurements

    EXPOSE 8000
    ENTRYPOINT ["./attestation-transparency-service"]

    ARG REGISTRY=fluorite.azurecr.io
    ARG TAG=latest

    SAVE IMAGE --push ${REGISTRY}/attestation-transparency-service:${TAG}

domain-monitor:
    FROM +rust-builder
    
    CACHE /root/.cargo/registry
    CACHE /root/.cargo/git
    
    CACHE ./domain-monitor/target

    COPY ./libraries/provisioning-structs/ ./libraries/provisioning-structs/
    COPY ./libraries/attested-server-verifier/ ./libraries/attested-server-verifier/ 
    COPY ./libraries/attestation/ ./libraries/attestation/

    COPY ./domain-monitor/.cargo ./domain-monitor/.cargo
    COPY ./domain-monitor/rust-toolchain.toml ./domain-monitor/rust-toolchain.toml
    COPY ./domain-monitor/Cargo.toml ./domain-monitor/Cargo.toml
    COPY ./domain-monitor/Cargo.lock ./domain-monitor/Cargo.lock
    COPY ./domain-monitor/src/ ./domain-monitor/src/
    WORKDIR ./domain-monitor/

    RUN cargo build --release --locked
    # Since we are caching the build binary, save artifact can't find it
    # because it's in a different volume, so copy it out of the cache

    RUN cp ./target/release/domain-monitor /monitor
    
    SAVE ARTIFACT /monitor AS LOCAL ./domain-monitor/target/release/domain-monitor

domain-monitor-image:
    # Use a minimal base image for the final, smaller runtime image
    FROM ubuntu:25.04

    # Install necessary runtime dependencies
    RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        lsb-release \
        gnupg \
        libxml2-dev \
        libxmlsec1-dev \
        libclang-dev \
        && rm -rf /var/lib/apt/lists/*

    # Set the working directory in the container
    WORKDIR /app

    # Copy the pre-built binary from the GitHub Actions runner's context
    COPY +domain-monitor/monitor ./domain-monitor
    COPY ./measurements/ ./measurements
    COPY ./domain-monitor/static/ ./static/
    RUN mkdir -p ./certificates ./proofs

    EXPOSE 8000
    ENTRYPOINT ["./domain-monitor"]

    ARG REGISTRY=fluorite.azurecr.io
    ARG TAG=latest
    
    SAVE IMAGE --push ${REGISTRY}/domain-monitor:${TAG}
client:
    FROM +rust-builder
    
    CACHE /root/.cargo/registry
    CACHE /root/.cargo/git
    
    CACHE ./multinode-provisioning/examples/client/target

    COPY ./libraries/provisioning-structs/ ./libraries/provisioning-structs/
    COPY ./libraries/attested-server-verifier/ ./libraries/attested-server-verifier/ 
    COPY ./libraries/attestation/ ./libraries/attestation/

    COPY ./multinode-provisioning/examples/client/.cargo ./multinode-provisioning/examples/client/.cargo
    COPY ./multinode-provisioning/examples/client/rust-toolchain.toml ./multinode-provisioning/examples/client/rust-toolchain.toml
    COPY ./multinode-provisioning/examples/client/Cargo.toml ./multinode-provisioning/examples/client/Cargo.toml
    COPY ./multinode-provisioning/examples/client/Cargo.lock ./multinode-provisioning/examples/client/Cargo.lock
    COPY ./multinode-provisioning/examples/client/src/ ./multinode-provisioning/examples/client/src/
    WORKDIR ./multinode-provisioning/examples/client/

    RUN cargo build --release --locked

    # Since we are caching the build binary, save artifact can't find it
    # because it's in a different volume, so copy it out of the cache

    RUN cp ./target/release/client /client
    
    SAVE ARTIFACT /client AS LOCAL ./multinode-provisioning/examples/client/target/release/client

zarf-packages:
    BUILD +zarf-ray
    BUILD +zarf-ray-tl
    BUILD +zarf-nginx
    BUILD +zarf-nginx-self-ca

svsm:
    # https://coconut-svsm.github.io/svsm/installation/INSTALL/#building-the-coconut-svsm
    FROM +rust-builder

    # Additional deps for svsm
    RUN apt-get update && apt-get install -y clang libclang-dev cmake

    CACHE /root/.cargo/registry
    CACHE /root/.cargo/git

    RUN mkdir /root/svsm  && cd /root/svsm  && \
        commit_hash=2cc503f927b2a153b6d45f4647d14cdf421d4615 && \
        git init && \
        git remote add origin https://github.com/mithril-security/svsm/ && \
        # Fetch only the specific tested commit hash
        git fetch --depth 1 origin "${commit_hash}" && \
        git checkout "${commit_hash}^{commit}" && \
        git submodule update --init --depth 1 --jobs $(nproc)
    WORKDIR /root/svsm

    COPY +ovmf/OVMF.fd /root/OVMF.fd
    RUN FW_FILE=/root/OVMF.fd cargo xbuild --release configs/qemu-target.json

    RUN MEASUREMENT=$(./target/release/igvmmeasure bin/coconut-qemu.igvm measure -b) && \
        echo "{\"igvm_measurement\": \"$MEASUREMENT\"}" > baremetal_measurements.json

    SAVE ARTIFACT bin/coconut-qemu.igvm AS LOCAL ./coconut-svsm/coconut-qemu.igvm
    SAVE ARTIFACT baremetal_measurements.json AS LOCAL ./libraries/attestation/svsm-sev-attestation/baremetal_measurements.json

ovmf:
    # https://coconut-svsm.github.io/svsm/installation/INSTALL/#building-the-guest-firmware
    FROM ubuntu:25.04
    ENV DEBIAN_FRONTEND=noninteractive

    CACHE /var/cache/apt
    
    RUN apt-get update && apt-get install --assume-yes \
        build-essential \
        pkg-config \
        git \
        uuid-dev \
        python3 \
        nasm \
        iasl

    
    RUN mkdir edk2 && cd edk2 && \
        commit_hash=3dfa011985e1efd9df061bff65d97f8e98ee3022 && \
        git init && \
        git remote add origin https://github.com/coconut-svsm/edk2.git && \
        # Fetch only the specific tested commit
        git fetch --depth 1 origin "$commit_hash" && \
        git checkout "${commit_hash}^{commit}" && \
        git submodule update --init --depth 1 --jobs $(nproc)
    WORKDIR edk2

    
    ENV PYTHON3_ENABLE=TRUE
    ENV PYTHON_COMMAND=python3
    RUN make -C BaseTools/ \
        && . ./edksetup.sh --reconfig  \
        && build -a X64 -n 1 --no-cache -b RELEASE -t GCC5 -D TPM2_ENABLE -p OvmfPkg/OvmfPkgX64.dsc

    # The resulting OVMF should not change
    RUN echo "fd2b570be53d073bb3bda3a6ba71d081731e873df35f131892ceebb7961fceb2  ./Build/OvmfX64/RELEASE_GCC5/FV/OVMF.fd" | sha256sum --check

    SAVE ARTIFACT Build/OvmfX64/RELEASE_GCC5/FV/OVMF.fd
    SAVE ARTIFACT Build/OvmfX64/RELEASE_GCC5/FV/OVMF.fd AS LOCAL ./coconut-svsm/OVMF.fd

igvm:
    FROM +rust-builder

    RUN cargo install cargo-c cbindgen

    RUN mkdir igvm && cd igvm && \
        commit_hash=5d2b5a58e0b294e2adfc923ac4baddfd270eb5a8 && \
        git init && \
        git remote add origin https://github.com/microsoft/igvm && \
        # Fetch only the specific tested commit hash
        git fetch --depth 1 origin "$commit_hash" && \
        git checkout "${commit_hash}^{commit}"
    WORKDIR igvm

    RUN DESTDIR=$HOME/igvminst make -f igvm_c/Makefile install

    SAVE ARTIFACT $HOME/igvminst
    SAVE ARTIFACT $HOME/igvminst AS LOCAL igvminst

qemu:
    FROM ubuntu:25.04
    ENV DEBIAN_FRONTEND=noninteractive

    CACHE /var/cache/apt

    RUN apt-get update && apt-get install --assume-yes \
        wget \
        git \
        build-essential \
        libglib2.0-dev \
        libfdt-dev \
        libpixman-1-dev \
        zlib1g-dev \
        ninja-build \
        python3-pip \
        python3-venv

    COPY +igvm/igvminst /root/igvminst

    RUN mkdir qemu-svsm && cd qemu-svsm && \
        commit_hash=1c5aacdac96e3f13ac6f63c604eeb5677a7060da && \
        git init && \
        git remote add origin https://github.com/coconut-svsm/qemu && \
        # Fetch only the specific tested commit hash
        git fetch --depth 1 origin "$commit_hash" && \
        git checkout "${commit_hash}^{commit}"
    WORKDIR qemu-svsm

    RUN PKG_CONFIG_PATH=$HOME/igvminst/usr/lib/x86_64-linux-gnu/pkgconfig ./configure --target-list=x86_64-softmmu --disable-docs --enable-igvm --disable-tcg-interpreter --enable-slirp --enable-kvm --enable-vhost-kernel \
        && C_INCLUDE_PATH=$HOME/igvminst/usr/include/ LIBRARY_PATH=$HOME/igvminst/usr/lib/x86_64-linux-gnu ninja -C build/ \
        && DESTDIR=$HOME/qemu make install


    # Example of how to run qemu :
    # LD_LIBRARY_PATH=/root/igvminst/usr/lib/x86_64-linux-gnu/ \
    # /root/qemu/usr/local/bin/qemu-system-x86_64 -version
    
    SAVE ARTIFACT $HOME/qemu AS LOCAL qemu
    SAVE ARTIFACT $HOME/igvminst AS LOCAL igvminst
 
build-kernel-svsm:
    # https://coconut-svsm.github.io/svsm/installation/INSTALL/#preparing-the-host
    FROM ubuntu:25.04
    ENV DEBIAN_FRONTEND=noninteractive

    CACHE /var/cache/apt

    RUN apt-get update && apt-get install --assume-yes \
        git \
        build-essential \
        libglib2.0-dev \
        libfdt-dev \
        libpixman-1-dev \
        zlib1g-dev \
        ninja-build \
        flex \
        bison \
        libelf-dev \
        libssl-dev \
        bc \
        cpio \
        zstd \
        debhelper-compat \
        kmod \
        rsync
    
    RUN mkdir linux && cd linux && \
        commit_hash=3d7f4e43fb9b1b41f1f0ef09c8f6d770505e59ce && \
        git init && \
        git remote add origin https://github.com/coconut-svsm/linux && \
        # Fetch only the specific tested commit hash
        git fetch --depth 1 origin "$commit_hash" && \
        git checkout "${commit_hash}^{commit}"
    WORKDIR linux

    SAVE IMAGE build-kernel-svsm

build-guest-kernel-svsm:
    FROM +build-kernel-svsm
    COPY os-base/kernel-configs/guest_config .config # Overwrite config with one that has CONFIG_TCG_PLATFORM=y

    RUN make -j$(nproc) LOCALVERSION= bindeb-pkg

    # Copy just the kernel image and headers
    # Then install with sudo dpkg -i svsm-linux/*.deb; sudo reboot

    RUN mkdir svsm-linux
    RUN cp ../linux-image-6.11.0_6.11.0*.deb ../linux-headers-6.11.0_6.11.0*.deb  svsm-linux/

    SAVE ARTIFACT svsm-linux/
    SAVE ARTIFACT svsm-linux/ AS LOCAL svsm-linux-guest

build-host-kernel-svsm:
    FROM +build-kernel-svsm
    COPY os-base/kernel-configs/host_config .config

    RUN make -j$(nproc) LOCALVERSION= bindeb-pkg

    # Copy just the kernel image and headers
    # Then install with sudo dpkg -i svsm-linux/*.deb; sudo reboot
    
    RUN mkdir svsm-linux
    RUN cp ../linux-image-6.11.0_6.11.0*.deb ../linux-headers-6.11.0_6.11.0*.deb svsm-linux/

    # No need to save it for other jobs
    # SAVE ARTIFACT svsm-linux/
    SAVE ARTIFACT svsm-linux/ AS LOCAL svsm-linux-host

svsm-kernel: 
    BUILD +build-guest-kernel-svsm
    BUILD +build-host-kernel-svsm

# ==============================================================================
# GCP Shielded VM Notarizer OS Image
# ==============================================================================

gcp-shielded-vm-notarizer:
    FROM +rust-builder
    
    CACHE /root/.cargo/registry
    CACHE /root/.cargo/git
    
    CACHE ./gcp-shielded-vm-notarizer/target

    COPY ./libraries/attestation/ ./libraries/attestation/
    COPY ./gcp-shielded-vm-notarizer/rust-toolchain.toml ./gcp-shielded-vm-notarizer/rust-toolchain.toml
    COPY ./gcp-shielded-vm-notarizer/Cargo.toml ./gcp-shielded-vm-notarizer/Cargo.toml
    COPY ./gcp-shielded-vm-notarizer/Cargo.lock ./gcp-shielded-vm-notarizer/Cargo.lock
    COPY ./gcp-shielded-vm-notarizer/src/ ./gcp-shielded-vm-notarizer/src/
    WORKDIR ./gcp-shielded-vm-notarizer/

    RUN cargo build --release --locked
    
    # Since we are caching the build binary, save artifact can't find it
    # because it's in a different volume, so copy it out of the cache
    RUN cp ./target/release/gcp-shielded-vm-notarizer /gcp-shielded-vm-notarizer
    
    SAVE ARTIFACT /gcp-shielded-vm-notarizer AS LOCAL ./gcp-shielded-vm-notarizer/target/release/gcp-shielded-vm-notarizer

setup-gcp-notarizer-rootfs:
    FROM ubuntu:25.04

    ENV DEBIAN_FRONTEND=noninteractive

    RUN apt-get update && apt-get install --assume-yes --no-install-recommends curl ca-certificates git

    COPY gcp-notarizer-os/ gcp-notarizer-os/
    WORKDIR gcp-notarizer-os

    # Make sure file permissions are correct for mkosi.extra
    RUN find ./rootfs/mkosi.extra/ -type d -exec chmod 755 {} \;
    RUN find ./rootfs/mkosi.extra/ -type f -exec chmod 644 {} \;

    # Make postinst scripts executable
    RUN chmod +x ./rootfs/mkosi.postinst
    RUN chmod +x ./rootfs/mkosi.images/initrd/mkosi.postinst

    # Install the gcp-shielded-vm-notarizer binary
    RUN mkdir -p ./rootfs/mkosi.extra/opt/
    COPY +gcp-shielded-vm-notarizer/gcp-shielded-vm-notarizer ./rootfs/mkosi.extra/opt/gcp-shielded-vm-notarizer
    RUN chmod +x ./rootfs/mkosi.extra/opt/gcp-shielded-vm-notarizer

    # Render the mkosi.conf template
    COPY +uv/uv /usr/local/bin/uv
    COPY os-base/render_template/ render_template/
    RUN uv tool install render_template/
    
    ARG debug = false

    RUN echo "debug: $debug" > config.yaml

    RUN /root/.local/bin/render_template ./config.yaml ./rootfs/mkosi.conf.j2

    SAVE ARTIFACT ./rootfs

gcp-notarizer-os:
    FROM +mkosi-builder

    COPY +setup-gcp-notarizer-rootfs/rootfs ./rootfs

    CACHE ./rootfs/mkosi.cache
    RUN --privileged /root/.local/bin/mkosi -C ./rootfs/

    # Compute the golden PCR4 for the os image and save
    COPY scripts/compute_measurements.py scripts/compute_measurements.py 
    RUN --privileged python3 scripts/compute_measurements.py ./rootfs/build/disk

    COPY measurements/measurements_gcp_cvm.json measurements/measurements_gcp_cvm.json
    RUN jq -n \
        --slurpfile pcr_data measurements/measurements_gcp_cvm.json \
        --slurpfile os_data os-measurement.json \
        '{golden_pcr_data: $pcr_data[0][0], expected_os_image_measurement: $os_data[0].fluoriteos_pcr4}' \
        > gcp_notarizer_measurements.json

    SAVE ARTIFACT gcp_notarizer_measurements.json AS LOCAL libraries/attestation/gcp-shielded-vm-attestation/gcp_notarizer_measurements.json

    ARG output_dir = "./gcp-cvm-notarizer/"

    SAVE ARTIFACT os-measurement.json AS LOCAL $output_dir/os-measurement.json
    SAVE ARTIFACT ./rootfs/build/disk AS LOCAL $output_dir/disk.raw
    SAVE ARTIFACT ./rootfs/build/disk.manifest AS LOCAL $output_dir/disk.manifest