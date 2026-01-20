# Start from an nvcr.io/nvidia/cuda:13.1.0-base-ubuntu24.04
FROM nvcr.io/nvidia/cuda:13.1.0-base-ubuntu24.04

WORKDIR /app

# 1. Install prerequisites: git and python3-venv, and curl
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3-venv \
    curl \
    git && \
    rm -rf /var/lib/apt/lists/*

# 2. Install 'uv'
RUN curl -LsSf https://astral.sh/uv/0.9.25/install.sh | sh

# 3. Clone the repository
RUN git clone --depth 1 https://github.com/mithril-security/nvtrust.git

# 4. Set the final entry point for the container
WORKDIR /app/nvtrust/guest_tools

# 5. Get dependencies
RUN /root/.local/bin/uv sync

# 6. Get and verify the GPU attestation
CMD ["/bin/sh", "-c", "/root/.local/bin/uv run --frozen --no-sync --no-cache python3 -m verifier.cc_admin && sleep infinity"]