# Validation checklist

Use this checklist to confirm the software authenticator behaves like a production FIDO2 security key after building the HID runner.

## Prerequisites

- `pc-hid-runner` binary built with the desired features.
- `liboqs` shared library from `prebuilt_liboqs/linux-x86_64` or `prebuilt_liboqs/linux-aarch64` on the `LD_LIBRARY_PATH`.
- A desktop environment with Chromium, Firefox, or another browser capable of WebAuthn.
- libfido2 tools (`fido2-token`, `fido2-assert`) installed for command-line validation.

## Checklist

1. **Start the runner**
   - Launch the service in the foreground: `cargo run -p pc-hid-runner -- start --foreground`.
   - Omit `--foreground` if you prefer to daemonise the service and monitor it via the log file in the state directory.
   - Confirm that a new `hidraw` node appears and is owned by the secure group specified in `contrib/udev/70-feitian-authenticator.rules`.
   - Run `fido2-token -L` and ensure the authenticator is detected with AAGUID and protocol listings.

2. **WebAuthn registration**
   - Visit [https://webauthn.io](https://webauthn.io) in a supported browser.
   - Perform a new credential registration with default options.
   - Verify that the prompt completes without manual UP (unless `--manual-user-presence` is enabled) and that the attestation object reports the expected AAGUID.

3. **WebAuthn authentication**
   - On the same site, trigger an authentication and ensure the credential created above can sign challenges successfully.
   - Confirm keepalive pings arrive every ~100ms while the request is pending (browser developer tools show HID traffic) and that the UI does not time out.

4. **Concurrent CTAP sessions**
   - Run `fido2-token -I <device>` to fetch device information while a browser session is active.
   - Ensure both operations complete and that the runner logs show interleaved CTAPHID transactions without resets.

5. **Timeout handling**
   - Start an authentication on webauthn.io and, without confirming, wait for the browser to timeout.
   - Confirm the runner logs a cancelled request and the CLI remains responsive.

6. **Manual user presence**
   - Restart the service with `--manual-user-presence` (for example `cargo run -p pc-hid-runner -- start --foreground --manual-user-presence`) and repeat the registration and authentication flows.
   - Ensure prompts wait for CLI confirmation (or whichever manual mechanism is configured) before proceeding.

7. **Shutdown hygiene**
   - Stop the service with `cargo run -p pc-hid-runner -- stop`.
   - Verify `/dev/hidraw*` no longer contains the virtual device and `/sys/class/hidraw/*` entries disappear, confirming UHID teardown executed cleanly.

Record the date, host OS, kernel version, and commit SHA when filing validation results.
