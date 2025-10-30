#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "Usage: $0 <hidraw-device> [pin]" >&2
    exit 1
fi

device="$1"
pin="${2:-123456}"

# Explicitly request the classic CTAP2 PIN/UV protocol (2) to verify fallback works.
FIDO2_PIN_PROTOCOL=2 fido2-token -S "$device" "$pin"
FIDO2_PIN_PROTOCOL=2 fido2-token -V "$device" "$pin"
