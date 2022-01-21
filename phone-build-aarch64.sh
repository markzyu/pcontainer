#!/bin/bash
TARGET=${1:-dc177}
cargo build --target=aarch64-unknown-linux-musl --release
scp target/aarch64-unknown-linux-musl/release/dockify "$TARGET":