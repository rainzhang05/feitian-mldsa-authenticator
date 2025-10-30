# HID Runner Manual Validation

The automated tests cover packet framing and basic CTAP2 echo flows, but each
release should also verify the transport with a real WebAuthn relying party.

1. Build the runner and start it with the default options:
   ```bash
   cargo build -p pc-hid-runner
   sudo target/debug/pc-hid-runner
   ```
2. Confirm the device is discoverable by the OS and tooling:
   ```bash
   sudo fido2-token -L
   sudo fido2-token -I /dev/hidrawX   # replace with the device path from -L
   ```
3. Visit [https://webauthn.io](https://webauthn.io) in a Chromium-based browser.
   Use **"Register"** to create a credential and **"Authenticate"** to exercise
   the existing credential. The runner defaults to automatic user presence, so
   both operations should complete without additional prompts.
4. Repeat the authenticate flow with the `--manual-user-presence` flag to ensure
   the transport surfaces keepalive status updates correctly.

For environments without direct access to `/dev/uhid`, you can enable the
optional end-to-end checks by exporting `PC_HID_RUNNER_E2E=1` and running the
integration tests or the `ci/hid-e2e.sh` helper script under `sudo`.
