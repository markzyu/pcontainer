#!/bin/bash
TARGET=${1:-dc156}
cargo build --target=armv7-unknown-linux-musleabihf --release
scp target/armv7-unknown-linux-musleabihf/release/dockify "$TARGET":