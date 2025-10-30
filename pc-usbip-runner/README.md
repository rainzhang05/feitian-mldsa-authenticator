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
identifies itself using the supplied VID/PID and product strings.

By default the example automatically fulfils user-presence checks so that the
VM workflow can progress without manual intervention. Pass
`--manual-user-presence` to disable the auto-confirmation and exercise the
normal polling path instead.

## Other examples

The previous `dummy` example is still available and can be run with
`cargo run --example dummy` if you need the simple CTAPHID vendor command
handler used during bring-up.
