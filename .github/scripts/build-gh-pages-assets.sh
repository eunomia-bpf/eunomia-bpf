#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
examples_root="${repo_root}/examples/bpftools"
ecc_bin="${ECC_BIN:-${repo_root}/compiler/workspace/bin/ecc-rs}"
wasi_clang="/opt/wasi-sdk/bin/clang"

if [[ ! -x "${ecc_bin}" ]]; then
  echo "ecc-rs is not available at ${ecc_bin}" >&2
  exit 1
fi

assert_file_exists() {
  local path="$1"

  if [[ ! -f "${path}" ]]; then
    echo "Expected asset is missing: ${path}" >&2
    exit 1
  fi
}

get_example_source() {
  local dir="$1"
  local sources=("${dir}"/*.bpf.c)

  if [[ ${#sources[@]} -eq 0 ]]; then
    echo "Expected exactly one *.bpf.c in ${dir}, found none" >&2
    exit 1
  fi
  if [[ ${#sources[@]} -ne 1 ]]; then
    echo "Expected exactly one *.bpf.c in ${dir}, found ${#sources[@]}" >&2
    exit 1
  fi
  printf '%s\n' "${sources[0]}"
}

get_example_header() {
  local source="$1"
  local stem
  stem="$(basename "${source}" .bpf.c)"
  printf '%s\n' "${source%.bpf.c}.h"
}

build_package_asset() {
  local dir="$1"
  local source
  source="$(get_example_source "${dir}")"
  local name
  name="$(basename "${source}" .bpf.c)"
  local header
  header="$(get_example_header "${source}")"

  echo "Building ${name}/package.json"
  if [[ -f "${header}" ]]; then
    "${ecc_bin}" "${source}" "${header}"
  else
    "${ecc_bin}" "${source}"
  fi
  assert_file_exists "${dir}/package.json"
}

build_passthrough_wasm_asset() {
  local dir="$1"
  local source
  source="$(get_example_source "${dir}")"
  local name
  name="$(basename "${source}" .bpf.c)"
  local header
  header="$(get_example_header "${source}")"
  local generated_source
  generated_source="$(mktemp "${dir}/.${name}.gh-pages-app.XXXXXX.c")"

  cat > "${generated_source}" <<'EOF'
#include <stdio.h>
#include <string.h>

#include "ewasm-skel.h"

int create_bpf(char *ebpf_json, int str_len);
int run_bpf(int id);
int wait_and_poll_bpf(int id);

int bpf_main(char *env_json, int str_len)
{
    (void)env_json;
    (void)str_len;

    int res = create_bpf(program_data, strlen(program_data));
    if (res < 0) {
        printf("create_bpf failed %d\n", res);
        return -1;
    }
    res = run_bpf(res);
    if (res < 0) {
        printf("run_bpf failed %d\n", res);
        return -1;
    }
    res = wait_and_poll_bpf(res);
    if (res < 0) {
        printf("wait_and_poll_bpf failed %d\n", res);
        return -1;
    }
    return 0;
}

int process_event(int ctx, char *event_json, int str_len)
{
    (void)ctx;
    printf("%.*s\n", str_len, event_json);
    return -1;
}
EOF

  echo "Building ${name}/app.wasm"
  if [[ -f "${header}" ]]; then
    "${ecc_bin}" "${source}" "${header}" --wasm-header
  else
    "${ecc_bin}" "${source}" --wasm-header
  fi
  assert_file_exists "${dir}/ewasm-skel.h"

  "${wasi_clang}" \
    --target=wasm32-wasi \
    -O0 -z stack-size=4096 -Wl,--initial-memory=65536 \
    --sysroot=/opt/wasi-sdk/share/wasi-sysroot \
    -I "${dir}" \
    -Wl,--export=all \
    -Wl,--export=bpf_main \
    -Wl,--export=process_event \
    -Wl,--strip-all,--no-entry \
    -Wl,--allow-undefined \
    -o "${dir}/${name}.wasm" "${generated_source}"

  cp "${dir}/${name}.wasm" "${dir}/app.wasm"
  rm -f "${generated_source}"

  assert_file_exists "${dir}/${name}.wasm"
  assert_file_exists "${dir}/app.wasm"
}

build_sigsnoop_wasm_asset() {
  local dir="${examples_root}/sigsnoop"

  [[ -x "${dir}/build.sh" ]] || {
    echo "Missing executable sigsnoop build script at ${dir}/build.sh" >&2
    exit 1
  }

  echo "Building sigsnoop/app.wasm"
  (
    cd "${dir}"
    ./build.sh
    cp sigsnoop.wasm app.wasm
  )

  assert_file_exists "${dir}/sigsnoop.wasm"
  assert_file_exists "${dir}/app.wasm"
}

for dir in "${examples_root}"/*; do
  [[ -d "${dir}" ]] || continue
  build_package_asset "${dir}"
done

[[ -x "${wasi_clang}" ]] || {
  echo "Missing required Wasm compiler at ${wasi_clang}" >&2
  exit 1
}

build_sigsnoop_wasm_asset
build_passthrough_wasm_asset "${examples_root}/opensnoop"
