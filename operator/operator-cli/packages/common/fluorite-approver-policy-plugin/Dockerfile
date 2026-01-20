# Build the approver-policy binary
FROM docker.io/library/golang:1.25.0 AS builder

WORKDIR /workspace

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# Download deps
RUN go mod download

# Copy the go source files
COPY main.go main.go

# Build
RUN CGO_ENABLED=0 go build -o fluorite-approver-policy-plugin main.go

FROM gcr.io/distroless/static-debian12
LABEL description="example cert-manager approver-policy plugin"

WORKDIR /
USER 1001
COPY --from=builder /workspace/fluorite-approver-policy-plugin /usr/bin/fluorite-approver-policy-plugin

ENTRYPOINT ["/usr/bin/fluorite-approver-policy-plugin"]
