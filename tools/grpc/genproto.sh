#!/usr/bin/env bash
# stolen from prometheus
#
# Generate all protobuf bindings.
# Run from repository root.

set -x
set -e
set -u

if ! [[ "$0" =~ "tools/grpc/genproto.sh" ]]; then
	echo "must be run from repository root"
	exit 255
fi

if ! [[ $(protoc --version) =~ "3.14" ]]; then
	echo "could not find protoc 3.14, is it installed + in PATH?"
	exit 255
fi

echo "installing plugins"
go install github.com/golang/protobuf/protoc-gen-go

echo "generating code"
protoc -I api \
       --go_out=plugins=grpc:. --go_opt=module=github.com/osrg/gobgp api/*.proto
