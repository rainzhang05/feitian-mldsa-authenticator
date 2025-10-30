use std::io::{self, ErrorKind};

use ctaphid_dispatch::{self, app::Command, DEFAULT_MESSAGE_SIZE};
use heapless_bytes::Bytes;
use log::{error, warn};
use trussed_host_runner::set_waiting;

pub const PACKET_SIZE: usize = 64;
pub const VERSION_MAJOR: u8 = 0;
pub const VERSION_MINOR: u8 = 1;
pub const VERSION_BUILD: u8 = 0;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub channel: u32,
    pub command: Command,
    pub length: u16,
    pub timestamp: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Response {
    pub channel: u32,
    pub command: Command,
    pub length: u16,
}

impl Response {
    pub fn from_request(request: Request, len: usize) -> Self {
        Self {
            channel: request.channel,
            command: request.command,
            length: len as u16,
        }
    }

    pub fn error_from_request(request: Request) -> Self {
        Self {
            channel: request.channel,
            command: Command::Error,
            length: 1,
        }
    }

    pub fn error_on_channel(channel: u32) -> Self {
        Self {
            channel,
            command: Command::Error,
            length: 1,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct MessageState {
    next_sequence: u8,
    transmitted: usize,
}

impl Default for MessageState {
    fn default() -> Self {
        Self {
            next_sequence: 0,
            transmitted: PACKET_SIZE - 7,
        }
    }
}

impl MessageState {
    fn absorb_packet(&mut self) {
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.transmitted += PACKET_SIZE - 5;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum State {
    Idle,
    Receiving((Request, MessageState)),
    WaitingOnAuthenticator(Request),
    WaitingToSend(Response),
    Sending((Response, MessageState)),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum AuthenticatorError {
    ChannelBusy,
    InvalidChannel,
    InvalidCommand,
    InvalidLength,
    InvalidSeq,
    Timeout,
}

impl From<AuthenticatorError> for u8 {
    fn from(err: AuthenticatorError) -> Self {
        match err {
            AuthenticatorError::InvalidCommand => 0x01,
            AuthenticatorError::InvalidLength => 0x03,
            AuthenticatorError::InvalidSeq => 0x04,
            AuthenticatorError::Timeout => 0x05,
            AuthenticatorError::ChannelBusy => 0x06,
            AuthenticatorError::InvalidChannel => 0x0B,
        }
    }
}

pub trait PacketWriter {
    fn write_packet(&mut self, packet: &[u8; PACKET_SIZE]) -> io::Result<()>;
}

pub struct HidFramer<'pipe, const N: usize = { DEFAULT_MESSAGE_SIZE }> {
    requester: ctaphid_dispatch::Requester<'pipe, N>,
    buffer: [u8; N],
    state: State,
    last_channel: u32,
    started_processing: bool,
    needs_keepalive: bool,
    last_millis: u32,
    implements: u8,
}

impl<'pipe, const N: usize> HidFramer<'pipe, N> {
    pub fn new(requester: ctaphid_dispatch::Requester<'pipe, N>) -> Self {
        Self {
            requester,
            buffer: [0u8; N],
            state: State::Idle,
            last_channel: 0,
            started_processing: false,
            needs_keepalive: false,
            last_millis: 0,
            implements: 0x05,
        }
    }

    pub fn reset(&mut self) {
        self.state = State::Idle;
        self.started_processing = false;
        self.needs_keepalive = false;
        let _ = self.requester.cancel();
        set_waiting(false);
    }

    pub fn handle_packet<W: PacketWriter>(
        &mut self,
        writer: &mut W,
        packet: &[u8; PACKET_SIZE],
        now: u32,
    ) {
        let channel = u32::from_be_bytes(packet[..4].try_into().unwrap());
        let is_initialization = (packet[4] >> 7) != 0;

        if is_initialization {
            let command_byte = packet[4] & !0x80;
            let command = match Command::try_from(command_byte) {
                Ok(command) => command,
                Err(_) => {
                    self.start_sending_error_on_channel(
                        writer,
                        channel,
                        AuthenticatorError::InvalidCommand,
                    );
                    return;
                }
            };

            let length = u16::from_be_bytes([packet[5], packet[6]]);
            if length as usize > self.buffer.len() {
                self.start_sending_error_on_channel(
                    writer,
                    channel,
                    AuthenticatorError::InvalidLength,
                );
                return;
            }

            self.buffer[..(length as usize).min(PACKET_SIZE - 7)].copy_from_slice(&packet[7..]);

            let request = Request {
                channel,
                command,
                length,
                timestamp: now,
            };

            if length as usize <= PACKET_SIZE - 7 {
                self.dispatch_request(writer, request);
            } else {
                self.state = State::Receiving((request, MessageState::default()));
            }
        } else {
            match &mut self.state {
                State::Receiving((request, state)) => {
                    if packet[4] != state.next_sequence {
                        self.start_sending_error(writer, *request, AuthenticatorError::InvalidSeq);
                        return;
                    }

                    let payload_length = request.length as usize;
                    if state.transmitted + (PACKET_SIZE - 5) < payload_length {
                        self.buffer[state.transmitted..][..PACKET_SIZE - 5]
                            .copy_from_slice(&packet[5..]);
                        state.absorb_packet();
                    } else {
                        let missing = payload_length - state.transmitted;
                        self.buffer[state.transmitted..payload_length]
                            .copy_from_slice(&packet[5..][..missing]);
                        self.dispatch_request(writer, *request);
                    }
                }
                _ => {
                    warn!("unexpected continuation packet");
                }
            }
        }
    }

    fn dispatch_request<W: PacketWriter>(&mut self, writer: &mut W, request: Request) {
        match request.command {
            Command::Init => {
                if request.length != 8 {
                    self.start_sending_error(writer, request, AuthenticatorError::InvalidLength);
                    return;
                }

                self.last_channel = self.last_channel.wrapping_add(1);
                self.buffer[8..12].copy_from_slice(&self.last_channel.to_be_bytes());
                self.buffer[12] = 2;
                self.buffer[13] = VERSION_MAJOR;
                self.buffer[14] = VERSION_MINOR;
                self.buffer[15] = VERSION_BUILD;
                self.buffer[16] = self.implements;

                let response = Response::from_request(request, 17);
                self.start_sending(writer, response);
            }
            Command::Ping => {
                let response = Response::from_request(request, request.length as usize);
                self.start_sending(writer, response);
            }
            Command::Cancel => {
                self.cancel_ongoing_activity();
                set_waiting(false);
            }
            Command::Error => {
                self.start_sending_error(writer, request, AuthenticatorError::InvalidCommand);
            }
            _ => {
                self.needs_keepalive = matches!(request.command, Command::Cbor | Command::Msg);
                let _ = self.requester.take_response();

                match self.requester.request((
                    request.command,
                    Bytes::from_slice(&self.buffer[..request.length as usize]).unwrap(),
                )) {
                    Ok(()) => {
                        self.state = State::WaitingOnAuthenticator(request);
                        self.started_processing = true;
                        if self.needs_keepalive {
                            set_waiting(true);
                        }
                    }
                    Err(_) => {
                        self.send_error_now(writer, request, AuthenticatorError::ChannelBusy);
                    }
                }
            }
        }
    }

    pub fn cancel_ongoing_activity(&mut self) {
        if let State::WaitingOnAuthenticator(_) = self.state {
            let _ = self.requester.cancel();
        }
        self.state = State::Idle;
        set_waiting(false);
    }

    pub fn did_start_processing(&mut self) -> bool {
        if self.started_processing {
            self.started_processing = false;
            true
        } else {
            false
        }
    }

    pub fn send_keepalive<W: PacketWriter>(
        &mut self,
        writer: &mut W,
        waiting_for_user: bool,
    ) -> io::Result<bool> {
        if let State::WaitingOnAuthenticator(request) = self.state {
            if !self.needs_keepalive {
                return Ok(false);
            }

            let mut packet = [0u8; PACKET_SIZE];
            packet[..4].copy_from_slice(&request.channel.to_be_bytes());
            packet[4] = 0x80 | Command::KeepAlive.into();
            packet[5..7].copy_from_slice(&1u16.to_be_bytes());
            packet[7] = if waiting_for_user { 0x02 } else { 0x01 };

            writer.write_packet(&packet)?;
            return Ok(true);
        }

        Ok(false)
    }

    pub fn check_timeout<W: PacketWriter>(&mut self, writer: &mut W, now: u32) {
        let last = self.last_millis;
        self.last_millis = now;
        if let State::Receiving((request, _)) = &mut self.state {
            if now.wrapping_sub(request.timestamp) > 550 {
                let request = *request;
                self.start_sending_error(writer, request, AuthenticatorError::Timeout);
                self.state = State::Idle;
            } else if now.wrapping_sub(last) > 200 {
                request.timestamp = now;
            }
        }
    }

    pub fn handle_response<W: PacketWriter>(&mut self, writer: &mut W) {
        if let State::WaitingOnAuthenticator(request) = self.state {
            if let Ok(response) = self.requester.response() {
                match &response.0 {
                    Err(ctaphid_dispatch::app::Error::InvalidCommand) => {
                        self.start_sending_error(
                            writer,
                            request,
                            AuthenticatorError::InvalidCommand,
                        );
                    }
                    Err(ctaphid_dispatch::app::Error::InvalidLength) => {
                        self.start_sending_error(
                            writer,
                            request,
                            AuthenticatorError::InvalidLength,
                        );
                    }
                    Err(ctaphid_dispatch::app::Error::NoResponse) => {}
                    Ok(message) => {
                        if message.len() > self.buffer.len() {
                            self.start_sending_error(
                                writer,
                                request,
                                AuthenticatorError::InvalidLength,
                            );
                        } else {
                            self.buffer[..message.len()].copy_from_slice(message);
                            let response = Response::from_request(request, message.len());
                            self.start_sending(writer, response);
                        }
                    }
                }
            }
        }
    }

    fn start_sending<W: PacketWriter>(&mut self, writer: &mut W, response: Response) {
        self.state = State::WaitingToSend(response);
        set_waiting(false);
        let _ = self.maybe_write_packet(writer);
    }

    fn start_sending_error<W: PacketWriter>(
        &mut self,
        writer: &mut W,
        request: Request,
        error: AuthenticatorError,
    ) {
        self.start_sending_error_on_channel(writer, request.channel, error);
    }

    fn start_sending_error_on_channel<W: PacketWriter>(
        &mut self,
        writer: &mut W,
        channel: u32,
        error: AuthenticatorError,
    ) {
        self.buffer[0] = error.into();
        let response = Response::error_on_channel(channel);
        self.start_sending(writer, response);
    }

    fn send_error_now<W: PacketWriter>(
        &mut self,
        writer: &mut W,
        request: Request,
        error: AuthenticatorError,
    ) {
        let prev_state = std::mem::replace(&mut self.state, State::Idle);
        let prev = self.buffer[0];
        self.buffer[0] = error.into();
        let response = Response::error_from_request(request);
        self.start_sending(writer, response);
        let _ = self.maybe_write_packet(writer);
        self.state = prev_state;
        self.buffer[0] = prev;
    }

    pub fn maybe_write_packet<W: PacketWriter>(&mut self, writer: &mut W) -> bool {
        match self.state.clone() {
            State::WaitingToSend(response) => {
                let mut packet = [0u8; PACKET_SIZE];
                packet[..4].copy_from_slice(&response.channel.to_be_bytes());
                packet[4] = response.command.into_u8() | 0x80;
                packet[5..7].copy_from_slice(&response.length.to_be_bytes());

                let fits = 7 + response.length as usize <= PACKET_SIZE;
                if fits {
                    packet[7..7 + response.length as usize]
                        .copy_from_slice(&self.buffer[..response.length as usize]);
                } else {
                    packet[7..].copy_from_slice(&self.buffer[..PACKET_SIZE - 7]);
                }

                match writer.write_packet(&packet) {
                    Ok(()) => {
                        if fits {
                            self.state = State::Idle;
                        } else {
                            self.state = State::Sending((response, MessageState::default()));
                        }
                        true
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => false,
                    Err(err) => {
                        error!("failed to write HID packet: {err}");
                        false
                    }
                }
            }
            State::Sending((response, mut state)) => {
                let mut packet = [0u8; PACKET_SIZE];
                packet[..4].copy_from_slice(&response.channel.to_be_bytes());
                packet[4] = state.next_sequence;

                let sent = state.transmitted;
                let remaining = response.length as usize - sent;
                let last_packet = 5 + remaining <= PACKET_SIZE;
                if last_packet {
                    packet[5..5 + remaining].copy_from_slice(&self.buffer[sent..][..remaining]);
                } else {
                    packet[5..].copy_from_slice(&self.buffer[sent..][..PACKET_SIZE - 5]);
                }

                match writer.write_packet(&packet) {
                    Ok(()) => {
                        if last_packet {
                            self.state = State::Idle;
                        } else {
                            state.absorb_packet();
                            self.state = State::Sending((response, state));
                        }
                        true
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => false,
                    Err(err) => {
                        error!("failed to write HID packet: {err}");
                        false
                    }
                }
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ctaphid_dispatch::{Channel, InterchangeResponse};

    #[derive(Default)]
    struct TestWriter {
        packets: Vec<[u8; PACKET_SIZE]>,
    }

    impl PacketWriter for TestWriter {
        fn write_packet(&mut self, packet: &[u8; PACKET_SIZE]) -> io::Result<()> {
            self.packets.push(*packet);
            Ok(())
        }
    }

    fn make_channel<const N: usize>() -> (
        ctaphid_dispatch::Requester<'static, N>,
        ctaphid_dispatch::Responder<'static, N>,
    ) {
        let channel = Box::leak(Box::new(Channel::<N>::new()));
        channel.split().unwrap()
    }

    fn build_init_packet(channel: u32, nonce: [u8; 8]) -> [u8; PACKET_SIZE] {
        let mut packet = [0u8; PACKET_SIZE];
        packet[..4].copy_from_slice(&channel.to_be_bytes());
        packet[4] = 0x80 | Command::Init.into();
        packet[5..7].copy_from_slice(&(nonce.len() as u16).to_be_bytes());
        packet[7..7 + nonce.len()].copy_from_slice(&nonce);
        packet
    }

    #[test]
    fn init_allocates_channel_and_echoes_nonce() {
        let (requester, _responder) = make_channel::<DEFAULT_MESSAGE_SIZE>();
        let mut framer = HidFramer::new(requester);
        let mut writer = TestWriter::default();

        let nonce = [0xAA; 8];
        let packet = build_init_packet(0xFFFF_FFFF, nonce);
        framer.handle_packet(&mut writer, &packet, 0);
        assert!(framer.maybe_write_packet(&mut writer));

        assert_eq!(writer.packets.len(), 1);
        let response = writer.packets[0];
        assert_eq!(&response[..4], &0xFFFF_FFFFu32.to_be_bytes());
        assert_eq!(response[4], 0x80 | Command::Init.into());
        assert_eq!(u16::from_be_bytes([response[5], response[6]]), 17);
        assert_eq!(&response[7..15], &nonce);
        let assigned_channel = u32::from_be_bytes(response[15..19].try_into().unwrap());
        assert_ne!(assigned_channel, 0);
    }

    #[test]
    fn fragmented_cbor_request_dispatches_full_payload() {
        let (requester, mut responder) = make_channel::<DEFAULT_MESSAGE_SIZE>();
        let mut framer = HidFramer::new(requester);
        let mut writer = TestWriter::default();

        let mut payload = [0u8; 80];
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let mut first = [0u8; PACKET_SIZE];
        first[..4].copy_from_slice(&1u32.to_be_bytes());
        first[4] = 0x80 | Command::Cbor.into();
        first[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        first[7..].copy_from_slice(&payload[..PACKET_SIZE - 7]);
        framer.handle_packet(&mut writer, &first, 1);

        let mut cont = [0u8; PACKET_SIZE];
        cont[..4].copy_from_slice(&1u32.to_be_bytes());
        cont[4] = 0;
        let remaining = payload.len() - (PACKET_SIZE - 7);
        cont[5..5 + remaining].copy_from_slice(&payload[PACKET_SIZE - 7..]);
        framer.handle_packet(&mut writer, &cont, 2);

        let (command, bytes) = responder.take_request().expect("request");
        assert_eq!(command, Command::Cbor);
        assert_eq!(&bytes[..payload.len()], &payload);

        let response = Bytes::from_slice(b"OK").unwrap();
        responder
            .respond(InterchangeResponse(Ok(response)))
            .unwrap();

        framer.handle_response(&mut writer);
        assert!(framer.maybe_write_packet(&mut writer));

        assert_eq!(writer.packets.len(), 1);
        let packet = writer.packets[0];
        assert_eq!(&packet[..4], &1u32.to_be_bytes());
        assert_eq!(packet[4], 0x80 | Command::Cbor.into());
        assert_eq!(u16::from_be_bytes([packet[5], packet[6]]), 2);
        assert_eq!(&packet[7..9], b"OK");
    }

    #[test]
    fn parallel_channel_request_reports_busy() {
        let (requester, mut responder) = make_channel::<DEFAULT_MESSAGE_SIZE>();
        let mut framer = HidFramer::new(requester);
        let mut writer = TestWriter::default();

        let mut msg = [0u8; PACKET_SIZE];
        msg[..4].copy_from_slice(&1u32.to_be_bytes());
        msg[4] = 0x80 | Command::Cbor.into();
        msg[5..7].copy_from_slice(&1u16.to_be_bytes());
        msg[7] = 0xA5;
        framer.handle_packet(&mut writer, &msg, 1);

        let (command, bytes) = responder.take_request().expect("request");
        assert_eq!(command, Command::Cbor);
        assert_eq!(bytes[0], 0xA5);

        let mut second = [0u8; PACKET_SIZE];
        second[..4].copy_from_slice(&2u32.to_be_bytes());
        second[4] = 0x80 | Command::Cbor.into();
        second[5..7].copy_from_slice(&1u16.to_be_bytes());
        second[7] = 0x01;
        framer.handle_packet(&mut writer, &second, 2);

        assert!(!writer.packets.is_empty());
        let packet = writer.packets.last().unwrap();
        assert_eq!(&packet[..4], &2u32.to_be_bytes());
        assert_eq!(packet[4], 0x80 | Command::Error.into());
        assert_eq!(packet[7], AuthenticatorError::ChannelBusy.into());
    }
}
