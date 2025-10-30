# Feitian FIDO2 Software Authenticator

Software authenticator implementing post-quantum ML-DSA 44/65/87 with a Trussed-based stack in Rust, using the liboqs library for ML-DSA algorithm implementations. The project includes a patched and modified PC USB/IP runner so you can develop and test without flashing hardware. It exposes a FIDO2/CTAP2 HID interface and CCID that browsers and tooling can use for WebAuthn.

Highlights
- Algorithms: ML-DSA 44/65/87, ES256.
- Transports: USB HID (CTAPHID). Optional CCID smartcard interface for smartcard-style applications.
- Runner: PC-USBIP runner to simulate a USB device and attach it locally via usbip/vhci-hcd.

## Tech stack

- Languages: Rust (core, runner, USB/IP), C (ML-DSA implmenetation in liboqs)
- Frameworks/Crates:
  - Trussed (secure application framework)
  - usbd-ctaphid (CTAP2 over USB HID)
  - usbip-device (USB/IP device-side stack; patched locally)
- Tools:
  - USB/IP userspace (usbip) + kernel module (vhci-hcd)
  - libfido2 (fido2-token) or python-fido2 (optional, for testing)

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

- pc-usbip-runner/ — Runner that simulates the USB authenticator over USB/IP
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
  - usbip (userspace) and vhci-hcd (kernel module)
- Recommended for testing:
  - libfido2-tools (provides fido2-token)

Install (example on Ubuntu/Debian)
```bash
# Rust (recommended):
curl https://sh.rustup.rs -sSf | sh

# System packages:
sudo apt update
sudo apt install -y build-essential pkg-config libclang-dev usbip libfido2-1 libfido2-dev libfido2-udev
# Optional testing tools:
sudo apt install -y libfido2-tools python3-pip
```

## Build

At the repository root:
```bash
# Debug build
cargo build

# Release build
cargo build --release
```

## Run the USB/IP runner

Terminal 1 — start the runner:
```bash
cd pc-usbip-runner
# Starting runner binary
RUST_LOG=info cargo run --release --example authenticator
```

Terminal 2 — attach via USB/IP and performing checks:
```bash
# Ensure kernel module is present
sudo modprobe vhci-hcd

# List exportable devices
sudo usbip list -r localhost

# Attach (replace busid "1-1" with what list shows)
sudo usbip attach -r localhost -b 1-1

# Verify
sudo usbip port
lsusb -d 1998:0616
```

Detaching/resetting:
```bash
sudo usbip detach -p 0 || true
sudo modprobe -r vhci-hcd; sudo modprobe vhci-hcd
```
