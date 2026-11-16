#!/bin/sh
# Reproduce the inherited single-file gRPC generator with pinned compiler/tools.
set -eu
GO_IMAGE=docker.io/library/golang:1.27.4-bookworm
export PROTOC_VERSION=29.4
export PROTOC_GEN_GO_VERSION=v1.4.3

docker run --rm --volume "$(pwd):/workspace" --workdir /workspace \
    -e PROTOC_VERSION -e PROTOC_GEN_GO_VERSION \
    -e OUTPUT_UID="$(id -u)" -e OUTPUT_GID="$(id -g)" \
    "${GO_IMAGE}" sh -eu -c '
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl unzip
    case "$(uname -m)" in
        x86_64) compiler_arch=x86_64 ;;
        aarch64) compiler_arch=aarch_64 ;;
        *) echo "Unsupported protobuf tooling architecture" >&2; exit 1 ;;
    esac
    curl -fsSL "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-${compiler_arch}.zip" -o /tmp/protoc.zip
    unzip -q /tmp/protoc.zip -d /tmp/protoc
    go install "github.com/golang/protobuf/protoc-gen-go@${PROTOC_GEN_GO_VERSION}"
    /tmp/protoc/bin/protoc -I. api.proto --go_out=plugins=grpc,paths=source_relative:walletrpc
    gofmt -w walletrpc/api.pb.go
    chown -R "$OUTPUT_UID:$OUTPUT_GID" walletrpc
    '
