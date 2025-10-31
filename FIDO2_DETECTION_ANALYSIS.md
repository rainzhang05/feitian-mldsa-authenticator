# FIDO2 Device Detection Analysis

## Current Status

Based on analysis of the "Software FIDO2 Authenticator Requirements.pdf", the implementation already meets most requirements:

### ✅ Correctly Implemented

1. **HID Descriptor**
   - Usage Page: 0xF1D0 (FIDO Alliance) ✓
   - Usage ID: 0x01 (CTAPHID) ✓
   - Report size: 64 bytes ✓
   - No Report IDs (as required) ✓
   - Input (0x20) and Output (0x21) reports ✓

2. **CTAPHID Protocol**
   - Proper packet framing with 4-byte CID, 1-byte command, 2-byte length ✓
   - INIT command response format (17 bytes) ✓
   - Channel allocation ✓
   - Error handling ✓

3. **Capability Flags**
   - CAPABILITY_CBOR (0x04): Set ✓
   - CAPABILITY_NMSG (0x08): Set ✓  [FIXED in commit 87445c7]
   - Combined value: 0x0C ✓

4. **CTAP2 Implementation**
   - GetInfo command supported ✓
   - AAGUID configured: `4645495449414E980616525A30310000` ✓
   - Protocol version 2.1.0 ✓
   - Supports Command::Cbor ✓

5. **USB Device Identity**
   - Vendor ID: 0x096e ✓
   - Product ID: 0x0858 ✓
   - BUS_USB (0x03) ✓

## Why Empty AAGUID in fido2-token?

The command `fido2-token -L` showing empty parentheses `( )` means:
- Device IS detected as FIDO HID (usage page 0xF1D0 recognized) ✓
- CTAPHID_INIT likely succeeds (device responds to enumeration)
- But GetInfo (via CTAPHID_CBOR) may not be returning data properly

## Debugging Steps

### 1. Verify Device is Running Fresh

After code changes, the device must be restarted:
```bash
# Stop the runner
cargo run -p pc-hid-runner -- stop

# Start fresh
RUST_LOG=debug cargo run -p pc-hid-runner -- start --foreground
```

### 2. Check UHID Device Creation

```bash
# In another terminal, check if hidraw appears
ls -l /dev/hidraw*

# Check sysfs for FIDO device
grep -r "HID_ID.*1998:0616" /sys/class/hidraw/*/device/uevent
```

### 3. Enable Debug Logging

The runner has `log-all` feature enabled for ctaphid-dispatch. Run with:
```bash
RUST_LOG=trace cargo run -p pc-hid-runner -- start --foreground
```

This will show:
- UHID events received (OUTPUT, SET_REPORT)
- CTAPHID frames parsed
- Commands dispatched (INIT, CBOR)
- Responses sent

### 4. Test CTAPHID_INIT Manually

Use libfido2 tools to test:
```bash
# List devices with verbose output
fido2-token -L

# Try to get info (should show AAGUID if working)
fido2-token -I /dev/hidrawN
```

Expected output from `fido2-token -I`:
```
proto: 0x02
major: 0x02
minor: 0x01
build: 0x00
caps: 0x0c (CBOR, NMSG)
aaguid: 46454954 49414e98 06165252 5a303100
```

### 5. Check for Common Issues

#### Issue: Stale UHID Device
If the device was running before the CAPABILITY_NMSG fix:
```bash
# Remove stale hidraw
sudo rm /dev/hidrawN  # where N is the device number

# Restart runner
cargo run -p pc-hid-runner -- stop
cargo run -p pc-hid-runner -- start --foreground
```

#### Issue: Permissions
Ensure /dev/uhid is accessible:
```bash
# Check permissions
ls -l /dev/uhid

# If needed, add user to group or run with sudo
sudo cargo run -p pc-hid-runner -- start --foreground
```

#### Issue: Multiple FIDO Devices
If you have hardware FIDO keys plugged in:
```bash
# List all hidraw devices
ls -l /dev/hidraw*

# Check which is the software authenticator
grep -r "HID_ID.*1998:0616" /sys/class/hidraw/*/device/uevent

# Or by vendor/product
fido2-token -L | grep "096e.*0858"
```

## Expected Behavior After Fix

With CAPABILITY_NMSG (0x08) bit set:

1. `fido2-token -L` should show:
   ```
   /dev/hidrawN: vendor=0x096e, product=0x0858 (Virtual FIDO Authenticator)
   ```

2. `fido2-token -I /dev/hidrawN` should display full GetInfo response including AAGUID

3. Browsers should detect the device and allow WebAuthn registration/authentication

## Key PDF Requirements Met

From "Software FIDO2 Authenticator Requirements.pdf":

1. ✅ "HID Usage Page 0xF1D0 (assigned to FIDO Alliance) with a Usage ID 0x01"
2. ✅ "64-byte HID reports (the max for USB full-speed)"
3. ✅ "Notably, no Report ID bytes are used"
4. ✅ "CAPABILITY_CBOR (0x04): If set to 1, authenticator implements CTAPHID_CBOR"
5. ✅ "CAPABILITY_NMSG (0x08): If set to 1, authenticator DOES NOT implement CTAPHID_MSG"
6. ✅ "Protocol version (2)" in INIT response byte 12
7. ✅ "Capabilities" in INIT response byte 16 should be 0x0C

## Next Steps

1. **Restart the device** to ensure new capability flags take effect
2. **Check logs** with RUST_LOG=trace to see CTAPHID command flow
3. **Verify hidraw node** is created and has correct permissions
4. **Test with fido2-token -I** to see detailed GetInfo response

If issues persist after restart, the debug logs will show:
- Which CTAPHID commands are being received
- Whether responses are being sent
- Any errors in command processing

## Additional Notes

The fix in commit 87445c7 addresses the exact issue described in the PDF:
> "CTAPHID capability mask never advertises CAPABILITY_NMSG, so hosts assume CTAPHID_MSG is implemented and fall back to U2F when our transport rejects it."

With CAPABILITY_NMSG now set, hosts will NOT probe for CTAPHID_MSG and will directly use CTAPHID_CBOR for CTAP2 operations, allowing GetInfo to return the AAGUID properly.
