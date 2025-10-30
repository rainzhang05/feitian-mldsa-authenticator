# PC USB/IP Runner

The `trussed-usbip` crate provides a USB/IP runner for Trussed-based
applications. The `authenticator` example wires the ML-DSA authenticator's
CTAP implementation into the runner so it can be exercised from a desktop
machine.

## Authenticator example

Build and run the example with `cargo run --example authenticator` or use the
Makefile target, which automatically starts the USB/IP device and attaches it
via `usbip`:

```sh
make -C pc-usbip-runner
```

The CLI accepts standard USB identity parameters and the authenticator AAGUID:

```text
Usage: authenticator [OPTIONS]

Options:
  -n, --product <PRODUCT>        USB product string [default: Feitian FIDO2 Software Authenticator (ML-DSA)]
  -m, --manufacturer <MANUFACTURER>
                                 USB manufacturer string [default: Feitian Technologies Co., Ltd.]
      --serial <SERIAL>          USB serial number [default: FEITIAN-PQC-001]
      --state-file <STATE_FILE>  Trussed state file (currently unused, reserved for future persistence) [default: trussed-state.bin]
  -v, --vid <VID>                USB VID [default: 0x1998]
  -p, --pid <PID>                USB PID [default: 0x0616]
      --aaguid <AAGUID>          Authenticator AAGUID as 32 hex characters (hyphens optional)
      --manual-user-presence     Require physical confirmation instead of automatically acknowledging presence
  -h, --help                     Print help information
  -V, --version                  Print version information
```

The provided options are forwarded to the USB/IP runner so the CTAPHID stack
identifies itself using the supplied VID/PID and product strings. The crate
enables the CTAPHID transport by default; enable the `ccid` feature when you
also want to expose the smart-card interface.

By default the example automatically fulfils user-presence checks so that the
VM workflow can progress without manual intervention. Pass
`--manual-user-presence` to disable the auto-confirmation and exercise the
normal polling path instead.

### Choosing the correct `liboqs` binaries

The ML-DSA and ML-KEM wrappers link against prebuilt `liboqs` artifacts. Pick
the directory that matches the target triple you're building for:

```sh
uname -m
```

* `aarch64` → use `prebuilt_liboqs/linux-aarch64`
* `x86_64` → populate `prebuilt_liboqs/linux-x86_64` with the headers and
  libraries from the [liboqs release artifacts][liboqs-release]

Because the chat environment cannot upload binary artifacts, the x86_64
directory is intentionally left empty in commits. When developing on an x86_64
system, download the official `liboqs` release tarball, extract the `lib` and
`include` directories and copy them into `prebuilt_liboqs/linux-x86_64/` before
building.

When running the compiled binary outside of `cargo run`, export
`LD_LIBRARY_PATH=/path/to/prebuilt_liboqs/<target>/lib` so the dynamic linker can
locate `liboqs.so`.

[liboqs-release]: https://github.com/open-quantum-safe/liboqs/releases

## USB/IP usage

Once the runner is active you can attach it using the standard usbip flow:

```sh
sudo modprobe vhci-hcd
sudo usbip list -r localhost
sudo usbip attach -r localhost -b 1-1
sudo usbip port
lsusb
```

The authenticator will then appear as a FIDO CTAPHID device and can be used
for registration and authentication ceremonies with WebAuthn-compatible
relying parties.
