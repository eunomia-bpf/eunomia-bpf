#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
examples_root="${repo_root}/examples/bpftools"
ecc_bin="${ECC_BIN:-${repo_root}/compiler/workspace/bin/ecc-rs}"

if [[ ! -x "${ecc_bin}" ]]; then
  echo "ecc-rs is not available at ${ecc_bin}" >&2
  exit 1
fi

build_package_asset() {
  local dir="$1"
  local name
  name="$(basename "${dir}")"
  local source="${dir}/${name}.bpf.c"
  local header="${dir}/${name}.h"

  if [[ ! -f "${source}" ]]; then
    return 0
  fi

  echo "Building ${name}/package.json"
  if [[ -f "${header}" ]]; then
    "${ecc_bin}" "${source}" "${header}"
  else
    "${ecc_bin}" "${source}"
  fi
}

for dir in "${examples_root}"/*; do
  [[ -d "${dir}" ]] || continue
  build_package_asset "${dir}"
done

sigsnoop_dir="${examples_root}/sigsnoop"
if [[ -x /opt/wasi-sdk/bin/clang && -x "${sigsnoop_dir}/build.sh" ]]; then
  echo "Building sigsnoop Wasm assets"
  (
    cd "${sigsnoop_dir}"
    ./build.sh
    cp sigsnoop.wasm app.wasm
  )
else
  echo "Skipping sigsnoop Wasm assets; /opt/wasi-sdk/bin/clang or build.sh is missing" >&2
fi
