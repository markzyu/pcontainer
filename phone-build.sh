#!/bin/bash
cargo build --target=armv7-unknown-linux-musleabihf --release
scp target/armv7-unknown-linux-musleabihf/release/dockify dc156: