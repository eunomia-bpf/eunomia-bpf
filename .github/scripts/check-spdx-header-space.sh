#!/usr/bin/env bash
set -euo pipefail

matches="$(git grep -n $'\u00a0SPDX-License-Identifier:' -- bpf-loader-rs compiler ecli eunomia-sdks || true)"

if [[ -n "$matches" ]]; then
  echo "Found non-breaking spaces in SPDX headers:"
  echo "$matches"
  exit 1
fi
