#!/bin/bash
set -xe

cargo build
for cfile in tests/fixtures/*.c; do
	dir=$(dirname "$cfile")
	base=$(basename "$cfile" .c)
	gcc -O3 -o "$dir/${base}.out" "$dir/${base}.c"
done

python3 -m unittest discover -s tests/ "$@"
