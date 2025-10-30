# HID Host Transport Design

## Goals
- Enable the authenticator to present a local HID interface via `/dev/uhid`, allowing host-side WebAuthn clients to communicate with the software token without USB/IP.
- Maintain protocol fidelity with CTAPHID while integrating cleanly with the existing `CtapApp` state machine and credential store.
- Provide a transport abstraction that can coexist with the current USB/IP implementation, sharing discovery, dispatch, and telemetry surfaces.
- Preserve deterministic behavior suitable for automated testing, CI, and reproducible demos.
- Document the lifecycle, concurrency requirements, and validation steps so engineering stakeholders can sign off before implementation begins.

## `/dev/uhid` Lifecycle
1. **Device creation** – Open `/dev/uhid` with `O_RDWR | O_CLOEXEC` and write a `UHID_CREATE2` event describing the authenticator (VID/PID, report descriptor, device strings). The descriptor should mirror the USB/IP device so relying parties see a consistent identity.
2. **Event loop** – Poll the file descriptor for readable events (e.g., `UHID_START`, `UHID_STOP`, `UHID_OPEN`, `UHID_CLOSE`, `UHID_GET_REPORT`, `UHID_SET_REPORT`). Forward outbound CTAPHID reports to `/dev/uhid` using `UHID_INPUT2` events.
3. **Interrupt handling** – For each `UHID_OUTPUT` event, parse the payload into CTAPHID packets and push them into the transport queue that feeds `CtapApp`.
4. **Shutdown** – On process exit, error, or explicit disable, send `UHID_DESTROY` and close the fd. Ensure this also happens on panic paths via `Drop` or scoped guards so a stale device node is not left behind.

## CTAPHID Packet Flow
- **Initialization** – Handle `CTAPHID_INIT` by generating or reusing the same nonce/Channel ID logic as the USB/IP backend to maintain consistent behavior. Responses are written back through `/dev/uhid` as interrupt-in reports.
- **Segmentation** – Reuse the existing packet framer (shared with USB/IP) for multi-packet commands. Outbound frames are sent sequentially; inbound frames are reassembled before dispatch.
- **Dispatch** – Once a complete CTAP command is assembled, hand it to `CtapApp::call_transport`, mirroring the USB/IP path. Responses follow the same segmentation logic in reverse.
- **Error handling** – Map transport errors (e.g., short writes, invalid report ids, channel timeouts) into CTAPHID status codes and surface metrics/logging for observability.

## Concurrency Model
- Run the transport inside a single async task (Tokio) that owns the `/dev/uhid` fd, using `tokio::io::unix::AsyncFd` for readiness notifications.
- Use an internal mpsc channel for packets heading into `CtapApp` and another for responses heading out to `/dev/uhid`, allowing backpressure and separation between HID IO and CTAP processing.
- Guard shared resources (nonce cache, channel mapping, device identity) with `Arc<Mutex<_>>` or single-thread ownership to avoid races.
- Ensure graceful shutdown by coordinating a cancellation token that closes channels, drains pending responses, and destroys the UHID device.

## Cleanup Expectations
- Destroy the UHID device on any transport stop to avoid ghost devices.
- Clear ephemeral channel state and nonce caches when the device closes so a new host session starts fresh while persistent credentials remain untouched.
- Emit structured logs on lifecycle transitions (create/open/close/destroy) to aid in debugging orphaned devices.

## Integration with `CtapApp`
- Introduce a trait (e.g., `Transport`) implemented by both USB/IP and UHID backends exposing `fn start(&self, CtapAppHandle)` and `fn stop(&self)`.
- `CtapAppHandle` encapsulates command dispatch (`call`) and response submission (`reply`), reusing the existing USB/IP glue logic.
- The runner selects a transport based on configuration, instantiating both in tests to validate parity. The shared trait allows dependency injection for fuzzing and integration harnesses.

## Transition Strategy from USB/IP
- Phase 1: Keep USB/IP as the default while building the UHID backend behind the shared `Transport` trait. Add feature flags/env vars to opt into UHID.
- Phase 2: Run both transports in automated tests; compare logs and attestation data to ensure parity.
- Phase 3: Update tooling (e.g., `pc-usbip-runner`) to accept `--transport usbip|uhid`, defaulting to UHID once stable.
- Provide documentation for switching transports, including fallback steps if UHID encounters kernel compatibility issues.

## Coexistence Model
- Both transports register with a central dispatcher that owns a single `CtapApp` instance. The dispatcher ensures only one command executes at a time, irrespective of transport, to avoid conflicting operations on shared state.
- Device identity (AAGUID, credential storage) lives within `CtapApp`, so switching transports does not alter persisted keys.
- Metrics and logging subsystems tag events with the transport name to help triage failures.

## Security Considerations
- **Device identity persistence** – Store UHID descriptor fields (VID/PID, serial) alongside USB/IP values to guarantee a stable identity across restarts.
- **Permission model** – Document required Linux capabilities (e.g., `CAP_SYS_ADMIN` or membership in the `input` group) and recommend running the transport under a dedicated service account.
- **Isolation** – Ensure the UHID backend runs in its own process or sandbox when integrated into desktop environments, preventing a compromised browser from escalating via shared memory or file descriptors.
- **Audit logging** – Record CTAP commands/responses (minus sensitive key material) for forensic review when enabled.

## Testing and Validation
- **libfido2 discovery** – Verify the device enumerates via `fido2-token -L` and responds to basic commands (`makeCredential`, `getAssertion`).
- **Browser flows** – Test registration and authentication in Chromium and Firefox using WebDriver automation, ensuring user presence (UP) semantics match existing USB/IP behavior.
- **Regression suite** – Extend existing integration tests to exercise both transports via the shared trait, running in CI on multiple kernels.
- **Stress and recovery** – Simulate transport resets, unplug events, and rapid reconnects to confirm cleanup logic works.

## Stakeholder Review
Before implementation begins, present this design to the CTAP, transport, and security stakeholders for review. Capture feedback, update this document as needed, and obtain written approval to ensure alignment on goals, lifecycle handling, coexistence strategy, and validation checkpoints.
