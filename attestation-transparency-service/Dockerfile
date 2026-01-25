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
COPY ./attestation-transparency-service/target/release/attestation-transparency-service ./attestation-transparency-service

ARG PLATFORM_MEASUREMENTS_PATH="../measurements"
COPY ${PLATFORM_MEASUREMENTS_PATH} ./measurements

EXPOSE 8000

CMD ["./attestation-transparency-service"]