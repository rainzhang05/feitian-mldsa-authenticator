# FIDO2 Software Authenticator

Software authenticator implementing post-quantum ML-DSA 44/65/87 with a Trussed-based stack in Rust, using the liboqs library for ML-DSA algorithm implementations. The host runner provisions a virtual HID token through `/dev/uhid`, letting browsers and libfido2 talk to the authenticator without custom kernel modules. A legacy USB/IP transport remains available for environments that still need it. The project exposes a FIDO2/CTAP2 HID interface and CCID that browsers and tooling can use for WebAuthn.

Highlights
- Algorithms: ML-DSA 44/65/87, ES256.
- Transports: USB HID (CTAPHID) presented through `/dev/uhid` or a Linux USB gadget. Optional CCID smartcard interface for smartcard-style applications.
- Runner: Host UHID runner that creates a virtual hidraw node and bridges CTAPHID to Trussed. A USB gadget backend exposes a real HID interface via configfs, and a legacy USB/IP backend remains for compatibility testing.

## Tech stack

- Languages: Rust (core, runner, USB/IP), C (ML-DSA implmenetation in liboqs)
- Frameworks/Crates:
  - Trussed (secure application framework)
  - ctaphid-dispatch (CTAP2 frame dispatcher)
  - nix (low-level syscalls and `/dev/uhid` access)
  - libudev (hidraw enumeration)
  - usbip-device (USB/IP device-side stack; patched locally, optional)
- Tools:
  - libfido2 (fido2-token) or python-fido2 (optional, for testing)
  - USB/IP userspace (usbip) + kernel module (vhci-hcd) — only when exercising the legacy runner

## Patches and runner tools

- Patched usbip-device (vendored under patches/usbip-device) to:
  - Cap IN transfer sizes to host-requested length (buffer leftovers)
  - Report device speed explicitly (Full-Speed vs High-Speed)
  - Improve EP0 (control) handling by clearing stale IN data on new SETUP
- PC USB/IP runner (pc-usbip-runner):
  - Exposes the authenticator as a virtual USB device
  - Can set the reported USB speed (FS/HS)
  - Handles CTAPHID/CCID endpoints and event loop/keepalive

## Project structure

- pc-hid-runner/ — Host-side HID runner that bridges `/dev/uhid` to the authenticator stack
- pc-usbip-runner/ — Legacy USB/IP runner that simulates a USB authenticator device
- patches/usbip-device/ — Vendored/modified usbip-device crate used by the runner
- docs/ — Documentation, notes, and troubleshooting (if present)
- Other Rust/C crates — Core authenticator logic, CTAP2 handlers, and ML-DSA crypto
  - Typical layout: Cargo workspaces for Rust crates, and a C library for ML-DSA

## Dependencies

System (Ubuntu/Debian)
- Required:
  - Rust toolchain (rustup recommended): rustc, cargo
  - C toolchain: build-essential (or clang)
  - libclang-dev (for bindgen, if used)
  - pkg-config
  - libudev-dev
- Recommended for testing:
  - libfido2-tools (provides fido2-token)
- usbip + vhci-hcd (only required for the legacy USB/IP runner)
- Linux USB gadget stack (libcomposite, usb_f_hid, and a UDC such as dummy_hcd) when running the gadget backend

Rust crates of note:
- `nix` (with the `user` feature enabled for permission checks)
- `libudev` (safe bindings to enumerate hidraw devices)
- `ctaphid-dispatch` (frames CTAP messages for the host transport)

Install (example on Ubuntu/Debian)
```bash
# Rust (recommended):
curl https://sh.rustup.rs -sSf | sh

# System packages:
sudo apt update
sudo apt install -y build-essential pkg-config libclang-dev libudev-dev
# Optional testing and legacy-runner tools:
sudo apt install -y libfido2-1 libfido2-dev libfido2-tools usbip python3-pip
```

## Build

At the repository root:
```bash
# Debug build
cargo build

# Release build
cargo build --release
```

## Select a liboqs bundle

Prebuilt ML-DSA binaries are supplied under `prebuilt_liboqs/`. Choose the directory that matches your host architecture, then add the `lib` folder to your `LD_LIBRARY_PATH` (or install the contents under `/usr/local`):

```bash
# For x86_64 Linux
export LD_LIBRARY_PATH="$PWD/prebuilt_liboqs/linux-x86_64/lib:${LD_LIBRARY_PATH:-}"

# For aarch64 Linux
export LD_LIBRARY_PATH="$PWD/prebuilt_liboqs/linux-aarch64/lib:${LD_LIBRARY_PATH:-}"
```

If you build liboqs yourself, ensure the resulting shared library matches the target architecture of the runner binary.

## Run the HID runner

The HID runner provisions a virtual authenticator through `/dev/uhid`, creating a `hidraw` node that browsers can use transparently. From the root of the repository: 
```bash
# Starting with clean state
sudo pkill -f pc-hid-runner || true
sudo rmmod uhid 2>/dev/null || true
sudo modprobe uhid

# Configure permission
echo 'KERNEL=="uhid", MODE="0660", GROUP="plugdev"' | sudo tee /etc/udev/rules.d/70-uhid.rules
sudo udevadm control --reload-rules
sudo udevadm trigger
sudo chown root:plugdev /dev/uhid
sudo chmod 660 /dev/uhid
newgrp plugdev

# Launching the runner
RUST_LOG=info cargo run -p pc-hid-runner -- start --foreground
```

Useful flags:

- `--state-dir <path>` — override the persistent storage directory (defaults to `$XDG_DATA_HOME/feitian-mldsa-authenticator`)
- `--manual-user-presence` — require manual approval of user presence (auto-UP remains the default)
- `--suppress-attestation` — mask attestation certs for privacy testing
- `--pqc-policy <prefer|required|disabled>` — choose the PQC PIN/UV transport policy

Omit `--foreground` to run the service as a background daemon. The CLI also exposes `status` and `stop` subcommands that inspect or terminate that daemonised instance.

## Run the USB gadget runner

The default backend provisions a configfs USB device that surfaces a real HID interface at `/dev/hidg0`. This requires the Linux USB gadget stack and an available USB Device Controller (UDC). On physical hardware, the UDC is provided by the SoC; on PCs or VMs you can load the `dummy_hcd` module to emulate one.

```bash
sudo RUST_LOG=info $(which cargo) run -p pc-hid-runner -- \
    start --gadget-udc dummy_udc.0 --foreground
```

The runner automatically loads the required gadget kernel modules (`libcomposite`, `usb_f_hid`, and `dummy_hcd`), cleans up any
stale configfs gadget directory, and ensures `/dev/hidg0` is accessible to the invoking user before starting. When the process
exits it tears the gadget down and releases the dummy UDC, so rerunning the command is enough to refresh the device.

The gadget runner writes its configuration to `/sys/kernel/config/usb_gadget/<gadget-name>` (default `feitian-pqc-authenticator`) and cleans it up automatically when the process exits or you invoke `pc-hid-runner stop`. Customise the gadget parameters with:

- `--gadget-root <path>` — alternate configfs mount point (defaults to `/sys/kernel/config/usb_gadget`).
- `--gadget-name <name>` — override the gadget directory name.
- `--gadget-udc <udc>` — explicitly choose the UDC instead of auto-detecting the first available entry in `/sys/class/udc`.
- `--gadget-max-power-ma <mA>` — advertised configuration power draw (defaults to 100 mA).
- `--gadget-usb-version <hex>` — USB specification version (bcdUSB) to advertise; defaults to `0x0200` (USB 2.0).

Like the UHID runner, the gadget backend persists state in the configured `--state-dir` and shares all other command-line options (AAGUID, VID/PID, PQC policy, and identity strings). To switch back to the legacy `/dev/uhid` transport, pass `--backend uhid` explicitly.
