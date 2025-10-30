#![cfg(target_os = "linux")]

mod common;

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use common::TestRunner;
use hidapi::HidDevice;

const PACKET_SIZE: usize = 64;
const BROADCAST_CID: u32 = 0xFFFF_FFFF;
const CMD_PING: u8 = 0x01;
const CMD_INIT: u8 = 0x06;
const CMD_CBOR: u8 = 0x10;
const CMD_KEEPALIVE: u8 = 0x3B;

#[test]
fn hid_runner_handles_ping_and_cbor() -> Result<()> {
    let runner = TestRunner::start().context("start HID runner")?;
    let mut device = runner
        .wait_for_device(Duration::from_secs(5))
        .context("open hid device")?;

    let (channel, init_reply) = ctaphid_init(&mut device)?;
    assert_eq!(init_reply.nonce.len(), 8);
    assert_eq!(init_reply.channel, channel);

    let mut ping_payload = Vec::with_capacity(120);
    for idx in 0..120u16 {
        ping_payload.push((idx % 251) as u8);
    }
    let ping_response = ctaphid_request(&mut device, channel, CMD_PING, &ping_payload)?;
    assert_eq!(ping_response, ping_payload, "ping response matches payload");

    let cbor_response = ctaphid_request(&mut device, channel, CMD_CBOR, &[0x04])?;
    assert!(
        !cbor_response.is_empty(),
        "CBOR response should include status and payload"
    );
    assert_eq!(cbor_response[0], 0x00, "CBOR status is CTAP2_OK");

    Ok(())
}

struct InitReply {
    nonce: [u8; 8],
    channel: u32,
}

fn ctaphid_init(device: &mut HidDevice) -> Result<(u32, InitReply)> {
    use rand::{rngs::OsRng, RngCore};

    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);

    let response = ctaphid_request(device, BROADCAST_CID, CMD_INIT, &nonce)?;
    if response.len() < 17 {
        return Err(anyhow!("short INIT response: {} bytes", response.len()));
    }
    if response[..8] != nonce {
        return Err(anyhow!("INIT nonce mismatch"));
    }
    let new_cid = u32::from_be_bytes(response[8..12].try_into().unwrap());
    Ok((
        new_cid,
        InitReply {
            nonce,
            channel: new_cid,
        },
    ))
}

fn ctaphid_request(
    device: &mut HidDevice,
    channel: u32,
    command: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    send_request(device, channel, command, payload).context("write CTAPHID request")?;
    read_response(device, channel).context("read CTAPHID response")
}

fn send_request(device: &mut HidDevice, channel: u32, command: u8, payload: &[u8]) -> Result<()> {
    let mut frame = [0u8; PACKET_SIZE];
    frame[..4].copy_from_slice(&channel.to_be_bytes());
    frame[4] = 0x80 | command;
    frame[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let mut sent = 0usize;
    let header_payload = payload.len().min(PACKET_SIZE - 7);
    frame[7..7 + header_payload].copy_from_slice(&payload[..header_payload]);
    write_packet(device, &frame)?;
    sent += header_payload;

    let mut sequence = 0u8;
    while sent < payload.len() {
        let mut cont = [0u8; PACKET_SIZE];
        cont[..4].copy_from_slice(&channel.to_be_bytes());
        cont[4] = sequence;
        sequence = sequence.wrapping_add(1);
        let chunk = (payload.len() - sent).min(PACKET_SIZE - 5);
        cont[5..5 + chunk].copy_from_slice(&payload[sent..sent + chunk]);
        write_packet(device, &cont)?;
        sent += chunk;
    }

    Ok(())
}

fn read_response(device: &mut HidDevice, channel: u32) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut expected_len: Option<usize> = None;
    let mut sequence = 0u8;
    loop {
        let packet = read_packet(device, Duration::from_millis(500))?;
        let packet_cid = u32::from_be_bytes(packet[..4].try_into().unwrap());
        if packet_cid != channel {
            continue;
        }

        let header = packet[4];
        if header & 0x80 != 0 {
            let cmd = header & 0x7F;
            if cmd == CMD_KEEPALIVE {
                expected_len = None;
                buffer.clear();
                continue;
            }
            let len = u16::from_be_bytes([packet[5], packet[6]]) as usize;
            buffer.clear();
            let chunk = len.min(PACKET_SIZE - 7);
            buffer.extend_from_slice(&packet[7..7 + chunk]);
            expected_len = Some(len);
            sequence = 0;
            if buffer.len() >= len {
                buffer.truncate(len);
                return Ok(buffer);
            }
        } else {
            if expected_len.is_none() {
                continue;
            }
            if header != sequence {
                return Err(anyhow!(
                    "unexpected continuation sequence: got {} expected {}",
                    header,
                    sequence
                ));
            }
            sequence = sequence.wrapping_add(1);
            let len = expected_len.unwrap();
            let already = buffer.len();
            if already >= len {
                continue;
            }
            let chunk = (len - already).min(PACKET_SIZE - 5);
            buffer.extend_from_slice(&packet[5..5 + chunk]);
            if buffer.len() >= len {
                buffer.truncate(len);
                return Ok(buffer);
            }
        }
    }
}

fn read_packet(device: &mut HidDevice, timeout: Duration) -> Result<[u8; PACKET_SIZE]> {
    let mut buf = [0u8; PACKET_SIZE + 1];
    loop {
        let len = device
            .read_timeout(&mut buf, timeout.as_millis() as i32)
            .context("read from hid device")?;
        if len == PACKET_SIZE {
            let mut packet = [0u8; PACKET_SIZE];
            packet.copy_from_slice(&buf[..PACKET_SIZE]);
            return Ok(packet);
        } else if len == PACKET_SIZE + 1 {
            let mut packet = [0u8; PACKET_SIZE];
            packet.copy_from_slice(&buf[1..=PACKET_SIZE]);
            return Ok(packet);
        } else if len == 0 {
            continue;
        } else {
            return Err(anyhow!("unexpected HID packet length: {}", len));
        }
    }
}

fn write_packet(device: &mut HidDevice, packet: &[u8; PACKET_SIZE]) -> Result<()> {
    let mut report = [0u8; PACKET_SIZE + 1];
    report[1..].copy_from_slice(packet);
    device.write(&report).context("write HID report")?;
    Ok(())
}
