#!/usr/bin/env bash
set -euo pipefail

librist_ref="${1:?usage: install-librist.sh REF [EXPECTED_VERSION]}"
expected_version="${2:-}"
runner_temp="${RUNNER_TEMP:-/tmp}"
source_dir="$(mktemp -d "${runner_temp}/librist-source.XXXXXX")"
build_dir="${source_dir}/build"

git clone --quiet https://code.videolan.org/rist/librist.git "${source_dir}"
git -C "${source_dir}" checkout --quiet --detach "${librist_ref}"

meson setup "${build_dir}" "${source_dir}" \
  --buildtype=release \
  --prefix=/usr/local \
  -Dbuiltin_cjson=true \
  -Dbuiltin_lz4=true \
  -Dbuiltin_mbedtls=true \
  -Dbuilt_tools=false \
  -Dtest=false
meson compile -C "${build_dir}"
sudo meson install -C "${build_dir}"
sudo ldconfig

actual_version="$(pkg-config --modversion librist)"
if [[ -n "${expected_version}" && "${actual_version}" != "${expected_version}" ]]; then
  echo "expected librist ${expected_version}, found ${actual_version}" >&2
  exit 1
fi

echo "installed librist ${actual_version} from ${librist_ref}"
