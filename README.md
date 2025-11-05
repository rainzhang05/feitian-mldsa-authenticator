# FIDO2 Software Authenticator

**Note: Running the authenticator with USB gadget requires the `dummy_hcd` kernel module, only supported on real Linux kernel, using any virtualized or containerized environment such as VMs will not launch the USB gadget successfully.**

Software authenticator implementing post-quantum ML-DSA 44/65/87 with a Trussed-based stack in Rust, using the liboqs library for ML-DSA algorithm implementations. The host runner provisions a virtual HID token through `/dev/uhid`, letting browsers and libfido2 talk to the authenticator without custom kernel modules. A legacy USB/IP transport remains available for environments that still need it. The project exposes a FIDO2/CTAP2 HID interface and CCID that browsers and tooling can use for WebAuthn.

Highlights
- Algorithms: ML-DSA 44/65/87, ES256.
- Transports: USB HID (CTAPHID) presented through `/dev/uhid` or a Linux USB gadget. Optional CCID smartcard interface for smartcard-style applications.
- Runner: Host UHID runner that creates a virtual hidraw node and bridges CTAPHID to Trussed. A USB gadget backend exposes a real HID interface via configfs, and a legacy USB/IP backend remains for compatibility testing.

## Tech stack

- Languages and FFI: Rust across the workspace crates, C via liboqs for ML-DSA and ML-KEM bindings consumed by `trussed-mldsa` and `trussed-mlkem`.
- Core crates:
  - `authenticator` - Trussed application that implements CTAP2/CTAPHID and CCID flows on top of the PQC wrappers.
  - `transport-core` - shared storage/state crate providing littlefs-backed persistence, attestation helpers, and CTAP/CCID glue code.
  - `pc-hid-runner` - host runner exposing `/dev/uhid` and USB gadget backends with daemon/service management.
  - `pc-usbip-runner` (`trussed-usbip`) - legacy USB/IP transport kept for regression coverage.
  - `trussed-mldsa` & `trussed-mlkem` - thin zeroise-aware wrappers around liboqs ML-DSA/ML-KEM exports.
- Key ecosystem crates: Trussed (patched to commit `024e0ec`), `ctaphid-dispatch`, `usbd-ctaphid`, `usbd-ccid`, `apdu-dispatch`, `littlefs2`, `ciborium`, `serde`, `rcgen`, `p256`, `chacha20`, `rand_chacha`, `nix`, `signal-hook`, `daemonize`, and `clap`.
- Tooling for validation: `libfido2`/`python-fido2` for host interoperability tests, USB/IP utilities for the legacy backend, and Linux USB gadget stack components when exercising real HID gadgets.

## Patches and runner tools

- Crate patches:
  - `trussed` is pinned to upstream commit `024e0ec` for the Trussed features used by the authenticator stack.
  - `usbip-device` is vendored under `patches/usbip-device` with fixes for packet sizing, speed reporting, and EP0 hygiene to stabilise the legacy USB/IP transport.
  - `ssmarshal` lives under `patches/ssmarshal` to guarantee the `no_std` feature set and serde 1.0 compatibility relied on by `transport-core`.
- Runner tooling:
  - `pc-hid-runner` offers `/dev/uhid` and USB gadget backends, foreground/background service modes, permission checks, and helpers aligned with the packaged `contrib/udev` rule and `systemd` service unit.
  - `pc-usbip-runner` continues to expose the authenticator over USB/IP, with examples under `pc-usbip-runner/examples/` for CTAPHID and CCID exercise.

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
|       |-- gadget.rs
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
- USB gadget support (configfs, `usb_f_hid`, `dummy_hcd` or a physical UDC) when running the gadget backend.
- Service integration helpers: `systemd` (to deploy `contrib/systemd/feitian-authenticator.service`) and udev (for `contrib/udev/70-feitian-authenticator.rules`).

**Rust crates of note**
- Transport and protocol layers: `ctaphid-dispatch`, `usbd-ctaphid`, `usbd-ccid`, `apdu-dispatch`, `transport-core`.
- Storage and serialization: `littlefs2`, `littlefs2-core`, `ciborium`, vendored `ssmarshal`, `serde`.
- Host runner and orchestration: `nix`, `signal-hook`, `daemonize`, `clap`, `heapless-bytes`.
- Cryptography: `trussed` (patched), `trussed-mldsa`, `trussed-mlkem`, `p256`, `rcgen`, `sha2`, `chacha20`, `rand_chacha`, `zeroize`.

**Install (example on Ubuntu/Debian)**
```bash
# Rust (recommended):
curl https://sh.rustup.rs -sSf | sh

# System packages:
sudo apt update
sudo apt install -y build-essential pkg-config libclang-dev libudev-dev \
    libfido2-1 libfido2-dev libfido2-tools usbip python3-pip \
    linux-modules-extra-$(uname -r)

# Load USB gadget modules (required for virtual HID devices)
sudo modprobe libcomposite
sudo modprobe usb_f_hid
sudo modprobe dummy_hcd

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

## Run the HID runner (Without USB Gadget)

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
sudo RUST_LOG=info $(which cargo) run -p pc-hid-runner -- start --gadget-udc dummy_udc.0 --foreground
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
