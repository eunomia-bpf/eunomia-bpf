#!/bin/sh

set -u

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output_root="${EUNOMIA_COPY_LIBS_ROOT:-$script_dir}"
debug_log="${output_root}/ld_debug_output"

LD_DEBUG=libs "$@" 2>"$debug_log"
library_paths=$(awk '/^.+calling init:/{print $4}' "$debug_log")

for library_path in $library_paths; do
    target_path="${output_root}/libs${library_path}"
    target_dir=$(dirname "$target_path")
    mkdir -p "$target_dir"
    cp "$library_path" "$target_path"
done
