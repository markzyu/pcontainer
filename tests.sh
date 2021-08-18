#!/bin/bash
set -xe
cargo build
python3 -m unittest discover -s tests/
