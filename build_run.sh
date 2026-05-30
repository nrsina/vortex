#!/bin/bash
set -e

echo "Building Vortex..."
cargo build

echo "Setting capabilities..."
sudo setcap cap_net_raw,cap_net_admin=eip target/debug/vortex

echo "Running Vortex..."
./target/debug/vortex
