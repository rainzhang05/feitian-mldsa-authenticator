# Developer Notes

## CTAPHID Channel Allocation

The UHID transport now assigns CTAPHID channel identifiers using a
cryptographically strong random number generator. Each broadcast `CTAPHID_INIT`
request results in a new 32-bit channel that satisfies the following rules:

- Values `0x00000000` and `0xFFFFFFFF` are never allocated.
- Previously issued channel identifiers remain reserved for the lifetime of the
  process so a collision triggers a retry with a fresh random value.
- Re-initializing over an existing, known channel keeps the same channel ID so
  hosts can recover in-flight sessions without re-enumerating via the broadcast
  channel.

The allocator performs bounded retries when it encounters a reserved value or a
collision. If all retries fail the host reports `CHANNEL_BUSY` to signal that no
additional channels can be issued at the moment.

These semantics ensure the virtual authenticator complies with the production
requirements for unpredictable channel identifiers while avoiding accidental
channel reuse.
