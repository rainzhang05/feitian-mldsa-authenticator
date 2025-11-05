# FIDO Software Authenticator

Software authenticator implementing post-quantum ML-DSA 44/65/87 with a Trussed-based stack in Rust, using the liboqs library for ML-DSA algorithm implementations. The host runner provisions a virtual HID token through `/dev/uhid`, letting browsers and libfido2 talk to the authenticator without custom kernel modules. A legacy USB/IP transport remains available for environments that still need it. The project exposes a FIDO2/CTAP2 HID interface and CCID that browsers and tooling can use for WebAuthn.

Highlights
- Algorithms: ML-DSA 44/65/87, ES256.
- Transports: USB HID (CTAPHID) presented through `/dev/uhid`. Optional CCID smartcard interface for smartcard-style applications.
- Runner: Host UHID runner that creates a virtual hidraw node and bridges CTAPHID to Trussed. Optional USB/IP backend for legacy testing.

## Tech stack

- Languages and FFI: Rust across the workspace crates, C via liboqs for ML-DSA and ML-KEM bindings consumed by `trussed-mldsa` and `trussed-mlkem`.
- Core crates:
  - `authenticator` - Trussed application that implements CTAP2/CTAPHID and CCID flows on top of the PQC wrappers.
  - `transport-core` - shared storage/state crate providing littlefs-backed persistence, attestation helpers, and CTAP/CCID glue code.
  - `pc-hid-runner` - host runner exposing `/dev/uhid`. 
  - `pc-usbip-runner` (`trussed-usbip`) - legacy USB/IP transport kept for regression coverage.
  - `trussed-mldsa` & `trussed-mlkem` - thin zeroise-aware wrappers around liboqs ML-DSA/ML-KEM exports.
- Key ecosystem crates: Trussed (patched to commit `024e0ec`), `ctaphid-dispatch`, `usbd-ctaphid`, `usbd-ccid`, `apdu-dispatch`, `littlefs2`, `ciborium`, `serde`, `rcgen`, `p256`, `chacha20`, `rand_chacha`, `nix`, `signal-hook`, `daemonize`, and `clap`.
- Tooling for validation: `libfido2`/`python-fido2` for host interoperability tests, and USB/IP utilities for the legacy backend. 

## Patches and runner tools

- Crate patches:
  - `trussed` is pinned to upstream commit `024e0ec` for the Trussed features used by the authenticator stack.
  - `usbip-device` is vendored under `patches/usbip-device` with fixes for packet sizing, speed reporting, and EP0 hygiene to stabilise the legacy USB/IP transport.
  - `ssmarshal` lives under `patches/ssmarshal` to guarantee the `no_std` feature set and serde 1.0 compatibility relied on by `transport-core`.
- Runner tooling:
  - `pc-hid-runner` offers `/dev/uhid`, foreground/background service modes, permission checks, and helpers aligned with the packaged `contrib/udev` rule and `systemd` service unit.
  - `pc-usbip-runner (patch)` continues to expose the authenticator over USB/IP, with examples under `pc-usbip-runner/examples/` for CTAPHID and CCID exercise.

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

**System (Linux host)**
- Rust toolchain via `rustup` (2021 edition-compatible toolchain recommended).
- A C toolchain and binutils (`nm`) for linking against liboqs from `prebuilt_liboqs/`.
- Optional testing utilities: `libfido2-tools`, `python3-fido2`, and the USB/IP userspace (`usbip`, `vhci-hcd`) for exercising the legacy transport.
- Service integration helpers: `systemd` (to deploy `contrib/systemd/feitian-authenticator.service`) and udev (for `contrib/udev/70-feitian-authenticator.rules`).

**Rust crates of note**
- Transport and protocol layers: `ctaphid-dispatch`, `usbd-ctaphid`, `usbd-ccid`, `apdu-dispatch`, `transport-core`.
- Storage and serialization: `littlefs2`, `littlefs2-core`, `ciborium`, vendored `ssmarshal`, `serde`.
- Host runner and orchestration: `nix`, `signal-hook`, `daemonize`, `clap`, `heapless-bytes`.
- Cryptography: `trussed` (patched), `trussed-mldsa`, `trussed-mlkem`, `p256`, `rcgen`, `sha2`, `chacha20`, `rand_chacha`, `zeroize`.

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
# At the repository root:
cargo build          # Debug build
cargo build --release  # Release build
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
