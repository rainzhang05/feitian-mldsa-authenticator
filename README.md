# FIDO Software Authenticator

Software authenticator implementing post-quantum ML-DSA 44/65/87 with a Trussed-based stack in Rust, using the liboqs library for ML-DSA algorithm implementations. The host runner provisions a virtual HID token through `/dev/uhid`, letting browsers and libfido2 talk to the authenticator without custom kernel modules. A legacy USB/IP transport remains available for environments that still need it. The project exposes a FIDO2/CTAP2 HID interface and CCID that browsers and tooling can use for WebAuthn.

Highlights
- Algorithms: ML-DSA 44/65/87, ES256.
- Transports: USB HID (CTAPHID) presented through `/dev/uhid`. Optional CCID smartcard interface for smartcard-style applications.
- Runner: Host UHID runner that creates a virtual hidraw node and bridges CTAPHID to Trussed. Optional USB/IP backend for legacy testing.

## Tech stack

- Languages: Rust across all workspace crates; C for the liboqs ML-DSA/ML-KEM backends; a small amount of shell/systemd glue under `contrib/`.
- Core crates: Trussed application framework, shared `transport-core` services, Rust wrappers `trussed-mldsa` and `trussed-mlkem`, CTAP/HID plumbing via `ctaphid-dispatch` + `usbd-ctaphid`, CCID support via `usbd-ccid`, CBOR tooling with `ciborium`, persistent storage via `littlefs2`, and zero-copy buffers using `heapless`/`heapless-bytes`.
- Runner/runtime: `pc-hid-runner` (UHID daemon with Clap 4 CLI, `daemonize`, permission checks via `nix` + `libudev`), optional `pc-usbip-runner` backend built on `transport-core` and `usb-device`, plus plug-in support for USB/IP and CCID transports.
- PQC + crypto: Prebuilt `liboqs` bundles surfaced through the `trussed-mldsa` and `trussed-mlkem` wrappers, classical ECC via `p256`, attestation scaffolding using `rcgen`, randomness sourced from `rand`/`rand_chacha`.
- Tooling: Companion tooling includes `libfido2`, `python-fido2`, and USB/IP (`usbip`, `vhci-hcd`) for exercising the runners end-to-end.

## Patches and runner tools

- `pc-hid-runner/`: main host service; provides start/stop/status CLI, daemonizes with log output, verifies `/dev/uhid` permissions, toggles manual user presence, attestation suppression, PQC policy, and can swap to a USB/IP backend when built with the `usbip-backend` feature.
- `pc-usbip-runner/`: legacy and testing runner backed by the `trussed-usbip` crate, instantiating CTAPHID and optional CCID endpoints over USB/IP while reusing `transport-core` state management.
- `patches/usbip-device/`: vendored fork of the upstream crate wired in through `[patch.crates-io]`, retaining support for capped IN transfers, explicit speed reporting, and clean EP0 SETUP handling expected by the runners.
- `patches/ssmarshal/`: local copy of `ssmarshal` that keeps the `no_std` serialization path Trussed relies on while avoiding upstream API drift.
- `contrib/`: deployment assets including `systemd` service units and `udev` rules for hardened HID permissions.

## Project structure

```
.
|-- authenticator/
|   |-- Cargo.toml
|   `-- src/
|       |-- ctap.rs
|       |-- ctap/
|       |   `-- tests.rs
|       `-- lib.rs
|-- contrib/
|   |-- systemd/
|   |   `-- feitian-authenticator.service
|   `-- udev/
|       `-- 70-feitian-authenticator.rules
|-- download-ripgrepSCJSfZ/
|   `-- tmp-file
|-- patches/
|   |-- ssmarshal/
|   `-- usbip-device/
|-- pc-hid-runner/
|   |-- Cargo.toml
|   `-- src/
|       |-- bin/
|       |   `-- authenticator.rs
|       |-- cli.rs
|       |-- lib.rs
|       |-- permissions.rs
|       |-- service.rs
|       |-- transport/
|       |   |-- ctaphid_host.rs
|       |   `-- mod.rs
|       `-- uhid.rs
|-- pc-usbip-runner/
|   |-- Cargo.toml
|   |-- Dockerfile
|   |-- Makefile
|   |-- README.md
|   |-- examples/
|   `-- src/
|-- prebuilt_liboqs/
|   |-- linux-aarch64/
|   |   |-- include/oqs/
|   |   `-- lib/
|   `-- linux-x86_64/
|       |-- include/oqs/
|       `-- lib/
|-- target/
|   `-- ... (build artifacts)
|-- transport-core/
|   |-- Cargo.toml
|   `-- src/
|       |-- ctap/
|       |-- lib.rs
|       |-- logging.rs
|       `-- state.rs
|-- trussed-mldsa/
|   |-- Cargo.toml
|   |-- build.rs
|   `-- src/lib.rs
|-- trussed-mlkem/
|   |-- Cargo.toml
|   |-- build.rs
|   `-- src/lib.rs
|-- Cargo.toml
`-- README.md
```

## Dependencies

System (Ubuntu/Debian)
- Required: Rust toolchain (rustup recommended), C toolchain (`build-essential` or `clang`), `pkg-config`, `libudev-dev`, `libclang-dev`.
- Optional/testing: `libfido2-tools`, `python3-pip` + `python-fido2`, `usbip` with the `vhci-hcd` kernel module, `systemd` if you plan to install the provided unit.
- Kernel modules: `uhid` for the HID runner, `vhci-hcd` when exercising the USB/IP backend.

Rust crates of note:
- `transport-core` (shared CTAP/CCID state, storage, and attestation helpers).
- `trussed-mldsa` / `trussed-mlkem` (liboqs-backed PQC bindings).
- `littlefs2`, `littlefs2-core`, `interchange`, `heapless`, `heapless-bytes` (persistent storage and zero-copy data paths).
- `rcgen`, `p256`, `rand`, `rand_chacha`, `ciborium` (cryptography, attestation, and CBOR support).
- `clap`, `daemonize`, `nix`, `libudev`, `signal-hook` (runner CLI and host integration).

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
