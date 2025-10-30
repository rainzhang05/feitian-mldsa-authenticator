# Validation and interoperability checklist

This guide covers starting the UHID-backed authenticator service and
exercising the validation flows described in the project documentation.

## Starting the authenticator

Use the CLI from the `pc-hid-runner` crate. During development you can
run it via Cargo:

```bash
cargo run -p pc-hid-runner -- start --foreground
```

`--foreground` keeps the process attached to the terminal so logs remain
visible. Dropping the flag daemonizes the service and redirects stdout
and stderr to `<state-dir>/authenticator.log` (the default state
location is `~/.local/share/feitian-mldsa-authenticator`).

When the crate is installed (`cargo install --path pc-hid-runner`), the
system-wide binaries expose the same interface:

```bash
pc-hid-runner start --foreground
pc-hid-runner status
pc-hid-runner stop
```

Add `--help` to either the global command or to the `start` subcommand to
review options for selecting the UHID backend, overriding VID/PID values,
choosing a PQC policy, and pointing at an alternate state directory.

## Validation flows

1. With the authenticator running, plug the UHID device into your HID
   stack (for example by launching a browser or the `fido2-token`
   utility) and ensure it enumerates as `Feitian FIDO2 Software
   Authenticator (ML-DSA)`.
2. Run the PQC PIN integration script to exercise the hybrid PIN path:

   ```bash
   sudo tests/integration/pin_flow_pqc.sh /dev/hidrawX 123456
   ```

3. Run the classic fallback script to confirm that legacy relying
   parties can still authenticate:

   ```bash
   sudo tests/integration/pin_flow_classic.sh /dev/hidrawX 123456
   ```

Replace `/dev/hidrawX` with the node exposed by the UHID transport. The
scripts automatically provision the correct PIN protocol and validate the
full registration/assertion flow with `libfido2`.
