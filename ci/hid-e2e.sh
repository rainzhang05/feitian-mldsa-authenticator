#!/usr/bin/env bash
set -euo pipefail

if [[ "${PC_HID_RUNNER_E2E:-}" != "1" ]]; then
  echo "PC_HID_RUNNER_E2E not set; skipping HID end-to-end script"
  exit 0
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "HID end-to-end script only runs on Linux"
  exit 0
fi

if [[ $EUID -ne 0 ]]; then
  echo "This script must be executed as root (access to /dev/uhid required)"
  exit 1
fi

if ! command -v fido2-token >/dev/null 2>&1; then
  echo "fido2-token not found in PATH"
  exit 1
fi

if [[ ! -x target/debug/pc-hid-runner ]]; then
  echo "Build the pc-hid-runner binary first (cargo build -p pc-hid-runner)"
  exit 1
fi

serial="E2E-$(date +%s)"
runner="target/debug/pc-hid-runner"

modprobe uhid >/dev/null 2>&1 || true

echo "Starting pc-hid-runner with serial ${serial}"
"${runner}" --serial "${serial}" --product "HID E2E Test" --manufacturer "CI" &
runner_pid=$!
trap 'kill ${runner_pid} 2>/dev/null || true' EXIT

find_hidraw() {
  local tries=60
  while (( tries > 0 )); do
    for entry in /sys/class/hidraw/hidraw*; do
      [[ -e "${entry}" ]] || continue
      if grep -q "HID_UNIQ=${serial}" "${entry}/device/uevent" 2>/dev/null; then
        echo "/dev/$(basename "${entry}")"
        return 0
      fi
    done
    sleep 0.2
    tries=$((tries - 1))
  done
  return 1
}

hidraw_node=$(find_hidraw)
if [[ -z "${hidraw_node}" ]]; then
  echo "Timed out waiting for hidraw node"
  exit 1
fi

echo "Running fido2-token -L"
list_output=$(fido2-token -L)
if [[ $? -ne 0 ]]; then
  echo "fido2-token -L failed"
  exit 1
fi

echo "${list_output}" | grep -q "${serial}" || {
  echo "fido2-token -L output did not include serial ${serial}";
  exit 1;
}

echo "Running fido2-token -I ${hidraw_node}"
if ! fido2-token -I "${hidraw_node}"; then
  echo "fido2-token -I failed"
  exit 1
fi

echo "HID end-to-end script completed successfully"
