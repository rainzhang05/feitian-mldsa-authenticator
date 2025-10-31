use std::{
    collections::{HashSet, VecDeque},
    convert::TryInto,
    fmt,
};

use log::{debug, info, warn};
use rand::{rngs::OsRng, CryptoRng, RngCore};

use crate::uhid::{CtapHidFrame, CTAPHID_FRAME_LEN};
use ctaphid_dispatch::{
    app::{App, Command, Error as AppError},
    Requester,
};
use heapless_bytes::Bytes;
use interchange::State as InterchangeState;

const PACKET_SIZE: usize = CTAPHID_FRAME_LEN;
const LOG_PREVIEW: usize = 8;
const CTAP_STATUS_OK: u8 = 0x00;
const CBOR_CMD_GET_INFO: u8 = 0x04;
const DEFAULT_MAX_MSG_SIZE: u16 = 1200;
const CBOR_CMD_CLIENT_PIN: u8 = 0x06;
const CBOR_CMD_BIO_ENROLLMENT: u8 = 0x40;
const CLIENT_PIN_KEY_SUBCOMMAND: u8 = 0x01;
const CLIENT_PIN_KEY_PIN_PROTOCOL: u8 = 0x02;
const CLIENT_PIN_SUBCMD_GET_RETRIES: u8 = 0x01;
const CLIENT_PIN_SUBCMD_GET_UV_RETRIES: u8 = 0x07;
const CTAP1_ERR_INVALID_COMMAND: u8 = 0x01;
const CTAP2_ERR_INVALID_PARAMETER: u8 = 0x02;
const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
const CTAP2_ERR_UNSUPPORTED_OPTION: u8 = 0x2B;
const CTAP2_ERR_PIN_NOT_SET: u8 = 0x36;
const CLIENT_PIN_DEFAULT_RETRIES: u8 = 8;
const CHANNEL_GENERATION_RETRY_LIMIT: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub build: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Request {
    channel: u32,
    command: Command,
    length: u16,
    timestamp: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Response {
    channel: u32,
    command: Command,
    length: u16,
}

impl Response {
    fn from_request_and_size(request: Request, size: usize) -> Self {
        Self {
            channel: request.channel,
            command: request.command,
            length: size as u16,
        }
    }

    fn error_on_channel(channel: u32) -> Self {
        Self {
            channel,
            command: Command::Error,
            length: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Copy, Clone)]
struct HexOption(Option<u8>);

impl fmt::Display for HexOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(value) => write!(f, "0x{value:02x}"),
            None => write!(f, "n/a"),
        }
    }
}

#[derive(Copy, Clone, Default)]
struct CborResponseInfo {
    payload_len: usize,
    cbor_len: usize,
    status: u8,
    sub_command: Option<u8>,
    pin_protocol: Option<u8>,
}

impl CborResponseInfo {
    fn new(payload_len: usize, status: u8) -> Self {
        let cbor_len = payload_len.saturating_sub(1);
        Self {
            payload_len,
            cbor_len,
            status,
            sub_command: None,
            pin_protocol: None,
        }
    }

    fn with_context(mut self, sub_command: Option<u8>, pin_protocol: Option<u8>) -> Self {
        self.sub_command = sub_command;
        self.pin_protocol = pin_protocol;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum State {
    Idle,
    Receiving {
        request: Request,
        message: MessageState,
    },
    WaitingOnAuthenticator {
        request: Request,
    },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum AuthenticatorError {
    ChannelBusy,
    InvalidChannel,
    InvalidCommand,
    InvalidLength,
    InvalidSeq,
    Timeout,
    Canceled,
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
            AuthenticatorError::Canceled => 0x2D,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeepaliveStatus {
    Processing = 1,
    UpNeeded = 2,
}

pub struct CtaphidHost<'pipe, const N: usize, R = OsRng> {
    requester: Requester<'pipe, N>,
    state: State,
    buffer: [u8; N],
    pending: VecDeque<CtapHidFrame>,
    allocated_channels: HashSet<u32>,
    rng: R,
    implements: u8,
    version: Version,
    started_processing: bool,
    needs_keepalive: bool,
    last_millis: u64,
}

impl<'pipe, const N: usize> CtaphidHost<'pipe, N, OsRng> {
    pub fn new(requester: Requester<'pipe, N>) -> Self {
        Self::with_rng(requester, OsRng)
    }
}

impl<'pipe, const N: usize, R> CtaphidHost<'pipe, N, R>
where
    R: RngCore + CryptoRng,
{
    pub fn with_rng(requester: Requester<'pipe, N>, rng: R) -> Self {
        Self {
            requester,
            state: State::Idle,
            buffer: [0u8; N],
            pending: VecDeque::new(),
            allocated_channels: HashSet::new(),
            rng,
            implements: 0x80,
            version: Version::default(),
            started_processing: false,
            needs_keepalive: false,
            last_millis: 0,
        }
    }

    pub fn set_version(&mut self, version: Version) {
        self.version = version;
    }

    pub fn set_capabilities(&mut self, implements: u8) {
        self.implements = implements;
    }

    pub fn handle_frame(&mut self, frame: &CtapHidFrame, timestamp_ms: u64) {
        self.last_millis = timestamp_ms;
        let packet = frame.as_bytes();
        let channel = u32::from_be_bytes(packet[..4].try_into().unwrap());
        let is_initialization = (packet[4] & 0x80) != 0;

        if is_initialization {
            let command_number = packet[4] & !0x80;
            let command = match Command::try_from(command_number) {
                Ok(command) => command,
                Err(_) => {
                    self.enqueue_error_on_channel(channel, AuthenticatorError::InvalidCommand);
                    return;
                }
            };

            let length = u16::from_be_bytes(packet[5..7].try_into().unwrap());
            let preview_len = usize::min(
                length as usize,
                usize::min(LOG_PREVIEW, packet.len().saturating_sub(7)),
            );
            debug!(
                "RX init cid={channel:08x} cmd=0x{command_number:02x} ({:?}) len={} preview={:02x?}",
                command,
                length,
                &packet[7..7 + preview_len]
            );
            let request = Request {
                channel,
                command,
                length,
                timestamp: timestamp_ms,
            };

            if !matches!(self.state, State::Idle) {
                if let State::WaitingOnAuthenticator { request: current } = self.state {
                    if command == Command::Cancel && channel == current.channel {
                        self.cancel_ongoing_activity();
                        return;
                    }
                    if channel == current.channel {
                        self.start_sending_error(current, AuthenticatorError::InvalidSeq);
                    } else {
                        self.send_error_now(request, AuthenticatorError::ChannelBusy);
                    }
                } else if let State::Receiving {
                    request: current, ..
                } = self.state
                {
                    if command == Command::Cancel && channel == current.channel {
                        self.cancel_ongoing_activity();
                        return;
                    }
                    if channel == current.channel {
                        self.start_sending_error(current, AuthenticatorError::InvalidSeq);
                    } else {
                        self.send_error_now(request, AuthenticatorError::ChannelBusy);
                    }
                }
                return;
            }

            if length as usize > self.buffer.len() {
                self.send_error_now(request, AuthenticatorError::InvalidLength);
                return;
            }

            if length as usize > PACKET_SIZE - 7 {
                self.buffer[..PACKET_SIZE - 7].copy_from_slice(&packet[7..]);
                self.state = State::Receiving {
                    request,
                    message: MessageState::default(),
                };
            } else {
                self.buffer[..length as usize].copy_from_slice(&packet[7..][..length as usize]);
                self.dispatch_request(request);
            }
        } else {
            let sequence = packet[4];
            match self.state {
                State::Receiving {
                    request,
                    mut message,
                } => {
                    if channel != request.channel {
                        return;
                    }
                    if sequence != message.next_sequence {
                        self.start_sending_error(request, AuthenticatorError::InvalidSeq);
                        return;
                    }

                    let payload_length = request.length as usize;
                    if payload_length > self.buffer.len() {
                        self.start_sending_error(request, AuthenticatorError::InvalidLength);
                        return;
                    }

                    if message.transmitted + (PACKET_SIZE - 5) < payload_length {
                        let preview_len = LOG_PREVIEW.min(PACKET_SIZE - 5);
                        debug!(
                            "RX cont cid={channel:08x} seq={} preview={:02x?}",
                            sequence,
                            &packet[5..5 + preview_len]
                        );
                        self.buffer[message.transmitted..message.transmitted + PACKET_SIZE - 5]
                            .copy_from_slice(&packet[5..]);
                        message.absorb_packet();
                        self.state = State::Receiving { request, message };
                    } else {
                        let missing = payload_length - message.transmitted;
                        self.buffer[message.transmitted..payload_length]
                            .copy_from_slice(&packet[5..][..missing]);
                        self.dispatch_request(request);
                    }
                }
                _ => {}
            }
        }
    }

    pub fn handle_timeout(&mut self, timestamp_ms: u64) {
        if let State::Receiving { request, .. } = self.state {
            if timestamp_ms >= request.timestamp + 550 {
                self.start_sending_error(request, AuthenticatorError::Timeout);
                self.state = State::Idle;
            }
        }
    }

    pub fn send_keepalive(&mut self, waiting_for_user_presence: bool) -> bool {
        if let State::WaitingOnAuthenticator { request } = self.state {
            if !self.needs_keepalive {
                return false;
            }

            let status = if waiting_for_user_presence {
                KeepaliveStatus::UpNeeded
            } else {
                KeepaliveStatus::Processing
            };
            self.enqueue_keepalive(request.channel, status);
            true
        } else {
            false
        }
    }

    pub fn poll_dispatch<'interrupt>(
        &mut self,
        dispatch: &mut ctaphid_dispatch::Dispatch<'pipe, 'interrupt, N>,
        apps: &mut [&mut dyn App<'interrupt, N>],
    ) -> bool {
        let mut did_work = false;
        while dispatch.poll(apps) {
            did_work = true;
        }

        if let State::WaitingOnAuthenticator { request } = self.state {
            if let Ok(response) = self.requester.response() {
                let outcome = match &response.0 {
                    Err(AppError::InvalidCommand) => Some(Err(AuthenticatorError::InvalidCommand)),
                    Err(AppError::InvalidLength) => Some(Err(AuthenticatorError::InvalidLength)),
                    Err(AppError::NoResponse) => Some(Err(AuthenticatorError::InvalidCommand)),
                    Ok(bytes) => {
                        let len = bytes.len();
                        self.buffer[..len].copy_from_slice(bytes);
                        Some(Ok(len))
                    }
                };
                if let Some(result) = outcome {
                    match result {
                        Ok(len) => {
                            let response = Response::from_request_and_size(request, len);
                            self.enqueue_response(response);
                            did_work = true;
                        }
                        Err(error) => {
                            self.start_sending_error(request, error);
                            did_work = true;
                        }
                    }
                }
                let _ = self.requester.take_response();
                self.state = State::Idle;
                self.needs_keepalive = false;
            }
        }

        did_work
    }

    pub fn has_pending_frames(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn next_outgoing_frame(&mut self) -> Option<CtapHidFrame> {
        self.pending.pop_front()
    }

    pub fn take_started_processing(&mut self) -> bool {
        if self.started_processing {
            self.started_processing = false;
            true
        } else {
            false
        }
    }

    fn dispatch_request(&mut self, request: Request) {
        match request.command {
            Command::Init => self.handle_init(request),
            Command::Ping => self.handle_ping(request),
            Command::Cancel => self.handle_cancel(request),
            _ => self.handle_application_request(request),
        }
    }

    fn handle_init(&mut self, request: Request) {
        if request.length != 8 {
            self.start_sending_error(request, AuthenticatorError::InvalidLength);
            return;
        }

        if request.channel == 0 {
            self.start_sending_error(request, AuthenticatorError::InvalidChannel);
            return;
        }

        let assigned_channel = if request.channel == 0xffffffff {
            match self.allocate_channel() {
                Ok(channel) => channel,
                Err(error) => {
                    self.start_sending_error(request, error);
                    return;
                }
            }
        } else if self.allocated_channels.contains(&request.channel) {
            request.channel
        } else {
            self.start_sending_error(request, AuthenticatorError::InvalidChannel);
            return;
        };

        let response = Response {
            channel: request.channel,
            command: request.command,
            length: 17,
        };
        self.buffer[8..12].copy_from_slice(&assigned_channel.to_be_bytes());
        self.buffer[12] = 2;
        self.buffer[13] = self.version.major;
        self.buffer[14] = self.version.minor;
        self.buffer[15] = self.version.build;
        self.buffer[16] = self.implements;
        self.enqueue_response(response);
        self.state = State::Idle;
    }

    fn handle_ping(&mut self, request: Request) {
        let response = Response::from_request_and_size(request, request.length as usize);
        self.enqueue_response(response);
        self.state = State::Idle;
    }

    fn handle_cancel(&mut self, request: Request) {
        if let State::WaitingOnAuthenticator { request: current } = self.state {
            if current.channel == request.channel {
                let _ = self.requester.cancel();
                self.enqueue_error_on_channel(current.channel, AuthenticatorError::Canceled);
                self.state = State::Idle;
                self.needs_keepalive = false;
            } else {
                self.enqueue_error_on_channel(request.channel, AuthenticatorError::InvalidChannel);
            }
        } else {
            self.enqueue_error_on_channel(request.channel, AuthenticatorError::InvalidSeq);
        }
    }

    fn handle_application_request(&mut self, request: Request) {
        if request.channel == 0xffffffff {
            self.start_sending_error(request, AuthenticatorError::InvalidChannel);
            return;
        }

        let payload_len = request.length as usize;
        if let Some(result) = self.try_handle_builtin(request, payload_len) {
            match result {
                Ok(info) => {
                    let response = Response::from_request_and_size(request, info.payload_len);
                    debug_assert_eq!(response.length as usize, info.payload_len);
                    self.enqueue_response(response);
                }
                Err(error) => {
                    self.start_sending_error(request, error);
                }
            }
            self.state = State::Idle;
            self.started_processing = true;
            self.needs_keepalive = false;
            return;
        }
        let payload = &self.buffer[..payload_len];
        match Bytes::<N>::from_slice(payload) {
            Ok(bytes) => {
                if matches!(self.requester.state(), InterchangeState::Responded) {
                    let _ = self.requester.take_response();
                }
                match self.requester.request((request.command, bytes)) {
                    Ok(()) => {
                        self.state = State::WaitingOnAuthenticator { request };
                        self.started_processing = true;
                        self.needs_keepalive = request.command == Command::Cbor;
                    }
                    Err(_) => {
                        self.send_error_now(request, AuthenticatorError::ChannelBusy);
                    }
                }
            }
            Err(_) => {
                self.start_sending_error(request, AuthenticatorError::InvalidLength);
            }
        }
    }

    fn cancel_ongoing_activity(&mut self) {
        if let State::WaitingOnAuthenticator { request } = self.state {
            let _ = self.requester.cancel();
            self.enqueue_error_on_channel(request.channel, AuthenticatorError::Canceled);
            self.state = State::Idle;
            self.needs_keepalive = false;
        }
    }

    fn enqueue_response(&mut self, response: Response) {
        let mut frame = [0u8; PACKET_SIZE];
        frame[..4].copy_from_slice(&response.channel.to_be_bytes());
        frame[4] = response.command.into_u8() | 0x80;
        frame[5..7].copy_from_slice(&response.length.to_be_bytes());
        let mut remaining = response.length as usize;
        let mut offset = 0usize;

        let first_copy = remaining.min(PACKET_SIZE - 7);
        frame[7..7 + first_copy].copy_from_slice(&self.buffer[..first_copy]);
        debug!(
            "TX init cid={:08x} cmd=0x{:02x} len={} preview={:02x?}",
            response.channel,
            response.command.into_u8(),
            response.length,
            &self.buffer[..usize::min(first_copy, LOG_PREVIEW)]
        );
        remaining -= first_copy;
        offset += first_copy;
        self.pending.push_back(CtapHidFrame::new(frame));

        let mut sequence: u8 = 0;
        while remaining > 0 {
            let mut cont = [0u8; PACKET_SIZE];
            cont[..4].copy_from_slice(&response.channel.to_be_bytes());
            cont[4] = sequence;
            sequence = sequence.wrapping_add(1);
            let chunk = remaining.min(PACKET_SIZE - 5);
            cont[5..5 + chunk].copy_from_slice(&self.buffer[offset..offset + chunk]);
            debug!(
                "TX cont cid={:08x} seq={} chunk_len={} preview={:02x?}",
                response.channel,
                sequence.wrapping_sub(1),
                chunk,
                &self.buffer[offset..offset + usize::min(chunk, LOG_PREVIEW)]
            );
            self.pending.push_back(CtapHidFrame::new(cont));
            offset += chunk;
            remaining -= chunk;
        }
    }

    fn enqueue_error_on_channel(&mut self, channel: u32, error: AuthenticatorError) {
        self.buffer[0] = error.into();
        let response = Response::error_on_channel(channel);
        self.enqueue_response(response);
    }

    fn start_sending_error(&mut self, request: Request, error: AuthenticatorError) {
        self.enqueue_error_on_channel(request.channel, error);
    }

    fn send_error_now(&mut self, request: Request, error: AuthenticatorError) {
        self.enqueue_error_on_channel(request.channel, error);
    }

    fn enqueue_keepalive(&mut self, channel: u32, status: KeepaliveStatus) {
        let mut frame = [0u8; PACKET_SIZE];
        frame[..4].copy_from_slice(&channel.to_be_bytes());
        frame[4] = Command::KeepAlive.into_u8() | 0x80;
        frame[5..7].copy_from_slice(&1u16.to_be_bytes());
        frame[7] = status as u8;
        debug!(
            "TX keepalive cid={channel:08x} status=0x{:02x}",
            status as u8
        );
        self.pending.push_back(CtapHidFrame::new(frame));
    }

    fn allocate_channel(&mut self) -> Result<u32, AuthenticatorError> {
        for _ in 0..CHANNEL_GENERATION_RETRY_LIMIT {
            let candidate = self.rng.next_u32();
            if candidate == 0 || candidate == 0xffffffff {
                continue;
            }
            if self.allocated_channels.insert(candidate) {
                return Ok(candidate);
            }
        }
        Err(AuthenticatorError::ChannelBusy)
    }

    fn try_handle_builtin(
        &mut self,
        request: Request,
        payload_len: usize,
    ) -> Option<Result<CborResponseInfo, AuthenticatorError>> {
        match request.command {
            Command::Cbor => self.handle_builtin_cbor(payload_len),
            _ => None,
        }
    }

    fn log_cbor_response(&self, cmd: u8, request_bcnt: usize, response: &CborResponseInfo) {
        debug!(
            "CBOR payload ({} bytes): {:02x?}",
            response.payload_len,
            &self.buffer[..response.payload_len]
        );
        info!(
            "CBOR cmd=0x{cmd:02x} status=0x{:02x} sub={} pinProtocol={} req_bcnt={} resp_bcnt={} resp_cbor_len={} resp_payload_len={}",
            response.status,
            HexOption(response.sub_command),
            HexOption(response.pin_protocol),
            request_bcnt,
            response.payload_len,
            response.cbor_len,
            response.payload_len,
        );
    }

    fn handle_builtin_cbor(
        &mut self,
        payload_len: usize,
    ) -> Option<Result<CborResponseInfo, AuthenticatorError>> {
        if payload_len == 0 {
            warn!("CBOR request missing subcommand");
            return Some(Err(AuthenticatorError::InvalidLength));
        }
        match self.buffer[0] {
            CBOR_CMD_GET_INFO => {
                let response = self.write_get_info_response();
                self.log_cbor_response(CBOR_CMD_GET_INFO, payload_len, &response);
                Some(Ok(response))
            }
            CBOR_CMD_CLIENT_PIN => {
                let response = self.write_client_pin_response(payload_len);
                self.log_cbor_response(CBOR_CMD_CLIENT_PIN, payload_len, &response);
                Some(Ok(response))
            }
            CBOR_CMD_BIO_ENROLLMENT => {
                let response = self.write_bio_enrollment_response(payload_len);
                self.log_cbor_response(CBOR_CMD_BIO_ENROLLMENT, payload_len, &response);
                Some(Ok(response))
            }
            _ => None,
        }
    }

    fn write_get_info_response(&mut self) -> CborResponseInfo {
        let mut offset = 0usize;
        self.buffer[offset] = CTAP_STATUS_OK;
        offset += 1;
        // Map with five entries
        self.buffer[offset] = 0xA5;
        offset += 1;
        // versions: ["FIDO_2_0"]
        self.buffer[offset] = 0x01;
        offset += 1;
        self.buffer[offset] = 0x81;
        offset += 1;
        self.buffer[offset] = 0x68; // text length 8
        offset += 1;
        self.buffer[offset..offset + 8].copy_from_slice(b"FIDO_2_0");
        offset += 8;
        // aaguid: 16 zero bytes
        self.buffer[offset] = 0x03;
        offset += 1;
        self.buffer[offset] = 0x50; // byte string length 16
        offset += 1;
        self.buffer[offset..offset + 16].fill(0);
        offset += 16;
        // options: {"clientPin": true, "uv": false}
        self.buffer[offset] = 0x04;
        offset += 1;
        self.buffer[offset] = 0xA2;
        offset += 1;
        self.buffer[offset] = 0x69; // text length 9
        offset += 1;
        self.buffer[offset..offset + 9].copy_from_slice(b"clientPin");
        offset += 9;
        self.buffer[offset] = 0xF5; // true
        offset += 1;
        self.buffer[offset] = 0x62; // text length 2
        offset += 1;
        self.buffer[offset..offset + 2].copy_from_slice(b"uv");
        offset += 2;
        self.buffer[offset] = 0xF4; // false
        offset += 1;
        // maxMsgSize: DEFAULT_MAX_MSG_SIZE
        self.buffer[offset] = 0x05;
        offset += 1;
        self.buffer[offset] = 0x19;
        offset += 1;
        self.buffer[offset..offset + 2].copy_from_slice(&DEFAULT_MAX_MSG_SIZE.to_be_bytes());
        offset += 2;
        // pinProtocols: [1]
        self.buffer[offset] = 0x06;
        offset += 1;
        self.buffer[offset] = 0x81;
        offset += 1;
        self.buffer[offset] = 0x01;
        offset += 1;
        debug_assert!(offset <= PACKET_SIZE - 7);
        debug_assert_eq!(self.buffer[1], 0xA5);
        CborResponseInfo::new(offset, CTAP_STATUS_OK)
    }

    fn write_bio_enrollment_response(&mut self, payload_len: usize) -> CborResponseInfo {
        let (sub_command, pin_protocol) = self.extract_subcommand_for_logging(payload_len);
        let status = CTAP1_ERR_INVALID_COMMAND;
        let payload_len = self.write_status_only_response(status);
        CborResponseInfo::new(payload_len, status).with_context(sub_command, pin_protocol)
    }

    fn extract_subcommand_for_logging(&self, payload_len: usize) -> (Option<u8>, Option<u8>) {
        if payload_len < 2 {
            return (None, None);
        }

        let reader = ClientPinRequestReader::new(&self.buffer[1..payload_len]);
        reader.read_partial().unwrap_or((None, None))
    }

    fn write_client_pin_response(&mut self, payload_len: usize) -> CborResponseInfo {
        if payload_len < 2 {
            warn!("ClientPIN request missing CBOR body");
            let status = CTAP2_ERR_INVALID_CBOR;
            let payload_len = self.write_status_only_response(status);
            return CborResponseInfo::new(payload_len, status);
        }

        let reader = ClientPinRequestReader::new(&self.buffer[1..payload_len]);
        let (sub_command, pin_protocol) = match reader.read() {
            Ok(values) => values,
            Err(status) => {
                warn!(
                    "ClientPIN request parse failure -> CTAP2 status 0x{:02x}",
                    status
                );
                let payload_len = self.write_status_only_response(status);
                return CborResponseInfo::new(payload_len, status);
            }
        };

        if pin_protocol != 1 {
            let status = CTAP2_ERR_INVALID_PARAMETER;
            warn!(
                "ClientPIN pinProtocol {} unsupported -> CTAP2 status 0x{:02x}",
                pin_protocol, status
            );
            let payload_len = self.write_status_only_response(status);
            return CborResponseInfo::new(payload_len, status)
                .with_context(Some(sub_command), Some(pin_protocol));
        }

        match sub_command {
            CLIENT_PIN_SUBCMD_GET_RETRIES => {
                CborResponseInfo::new(self.write_client_pin_get_retries(), CTAP_STATUS_OK)
                    .with_context(Some(sub_command), Some(pin_protocol))
            }
            CLIENT_PIN_SUBCMD_GET_UV_RETRIES => {
                let status = CTAP2_ERR_UNSUPPORTED_OPTION;
                let payload_len = self.write_status_only_response(status);
                CborResponseInfo::new(payload_len, status)
                    .with_context(Some(sub_command), Some(pin_protocol))
            }
            other => {
                let status = CTAP2_ERR_PIN_NOT_SET;
                warn!(
                    "ClientPIN subCommand=0x{:02x} unsupported -> CTAP2 status 0x{:02x}",
                    other, status
                );
                let payload_len = self.write_status_only_response(status);
                CborResponseInfo::new(payload_len, status)
                    .with_context(Some(sub_command), Some(pin_protocol))
            }
        }
    }

    fn write_client_pin_get_retries(&mut self) -> usize {
        let mut offset = 0usize;
        self.buffer[offset] = CTAP_STATUS_OK;
        offset += 1;
        self.buffer[offset] = 0xA1; // map with one entry
        offset += 1;
        self.buffer[offset] = 0x03; // retries key
        offset += 1;
        self.buffer[offset] = CLIENT_PIN_DEFAULT_RETRIES;
        offset += 1;
        offset
    }

    fn write_status_only_response(&mut self, status: u8) -> usize {
        self.buffer[0] = status;
        1
    }
}

struct ClientPinRequestReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ClientPinRequestReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read(self) -> Result<(u8, u8), u8> {
        let (sub_command, pin_protocol) = self.read_partial()?;
        let sub_command = sub_command.ok_or(CTAP2_ERR_INVALID_CBOR)?;
        let pin_protocol = pin_protocol.ok_or(CTAP2_ERR_INVALID_CBOR)?;
        Ok((sub_command, pin_protocol))
    }

    fn read_partial(mut self) -> Result<(Option<u8>, Option<u8>), u8> {
        let entries = self.read_map_len()?;
        let mut sub_command = None;
        let mut pin_protocol = None;

        for _ in 0..entries {
            let key = self.read_unsigned()?;
            match key {
                CLIENT_PIN_KEY_SUBCOMMAND => {
                    sub_command = Some(self.read_unsigned()?);
                }
                CLIENT_PIN_KEY_PIN_PROTOCOL => {
                    pin_protocol = Some(self.read_unsigned()?);
                }
                _ => {
                    self.skip_value()?;
                }
            }
        }

        Ok((sub_command, pin_protocol))
    }

    fn read_map_len(&mut self) -> Result<usize, u8> {
        let byte = self.next_byte().ok_or(CTAP2_ERR_INVALID_CBOR)?;
        match byte {
            0xA0..=0xB7 => Ok((byte & 0x1F) as usize),
            0xB8 => {
                let len = self.next_byte().ok_or(CTAP2_ERR_INVALID_CBOR)? as usize;
                Ok(len)
            }
            _ => Err(CTAP2_ERR_INVALID_CBOR),
        }
    }

    fn read_unsigned(&mut self) -> Result<u8, u8> {
        let byte = self.next_byte().ok_or(CTAP2_ERR_INVALID_CBOR)?;
        match byte {
            0x00..=0x17 => Ok(byte),
            0x18 => self.next_byte().ok_or(CTAP2_ERR_INVALID_CBOR),
            _ => Err(CTAP2_ERR_INVALID_CBOR),
        }
    }

    fn skip_value(&mut self) -> Result<(), u8> {
        let initial = self.next_byte().ok_or(CTAP2_ERR_INVALID_CBOR)?;
        match initial {
            0x00..=0x17 => Ok(()),
            0x18 => {
                self.next_byte().ok_or(CTAP2_ERR_INVALID_CBOR)?;
                Ok(())
            }
            0x19 => {
                self.consume(2)?;
                Ok(())
            }
            0x1A => {
                self.consume(4)?;
                Ok(())
            }
            0x1B => {
                self.consume(8)?;
                Ok(())
            }
            0x40..=0x57 => {
                let len = (initial & 0x1F) as usize;
                self.consume(len)?;
                Ok(())
            }
            0x58 => {
                let len = self.next_byte().ok_or(CTAP2_ERR_INVALID_CBOR)? as usize;
                self.consume(len)?;
                Ok(())
            }
            0x59 => {
                let len = self.read_u16()? as usize;
                self.consume(len)?;
                Ok(())
            }
            0x5A => {
                let len = self.read_u32()? as usize;
                self.consume(len)?;
                Ok(())
            }
            0x60..=0x77 => {
                let len = (initial & 0x1F) as usize;
                self.consume(len)?;
                Ok(())
            }
            0x78 => {
                let len = self.next_byte().ok_or(CTAP2_ERR_INVALID_CBOR)? as usize;
                self.consume(len)?;
                Ok(())
            }
            0x79 => {
                let len = self.read_u16()? as usize;
                self.consume(len)?;
                Ok(())
            }
            0x7A => {
                let len = self.read_u32()? as usize;
                self.consume(len)?;
                Ok(())
            }
            0xA0..=0xBF => {
                let entries = if initial <= 0xB7 {
                    (initial & 0x1F) as usize
                } else {
                    let len = if initial == 0xB8 {
                        self.next_byte().ok_or(CTAP2_ERR_INVALID_CBOR)? as usize
                    } else {
                        return Err(CTAP2_ERR_INVALID_CBOR);
                    };
                    len
                };
                for _ in 0..entries {
                    self.skip_value()?;
                    self.skip_value()?;
                }
                Ok(())
            }
            0x80..=0x9F => {
                let items = (initial & 0x1F) as usize;
                for _ in 0..items {
                    self.skip_value()?;
                }
                Ok(())
            }
            0xF4..=0xF7 => Ok(()),
            0xF9 => {
                self.consume(2)?;
                Ok(())
            }
            0xFA => {
                self.consume(4)?;
                Ok(())
            }
            0xFB => {
                self.consume(8)?;
                Ok(())
            }
            _ => Err(CTAP2_ERR_INVALID_CBOR),
        }
    }

    fn read_u16(&mut self) -> Result<u16, u8> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, u8> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn consume(&mut self, len: usize) -> Result<(), u8> {
        if self.offset + len > self.data.len() {
            return Err(CTAP2_ERR_INVALID_CBOR);
        }
        self.offset += len;
        Ok(())
    }

    fn take(&mut self, len: usize) -> Result<&[u8], u8> {
        if self.offset + len > self.data.len() {
            return Err(CTAP2_ERR_INVALID_CBOR);
        }
        let slice = &self.data[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice)
    }

    fn next_byte(&mut self) -> Option<u8> {
        if self.offset >= self.data.len() {
            None
        } else {
            let byte = self.data[self.offset];
            self.offset += 1;
            Some(byte)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CAPABILITY_CBOR, CAPABILITY_NMSG};
    use ctaphid_dispatch::{app::App, Channel, Dispatch, DEFAULT_MESSAGE_SIZE};
    use std::convert::TryInto;

    struct EchoApp;

    impl<'interrupt, const N: usize> App<'interrupt, N> for EchoApp {
        fn commands(&self) -> &'static [Command] {
            &[Command::Cbor]
        }

        fn call(
            &mut self,
            _command: Command,
            request: &[u8],
            response: &mut Bytes<N>,
        ) -> Result<(), AppError> {
            response.extend_from_slice(request).unwrap();
            Ok(())
        }
    }

    fn init_host() -> (
        CtaphidHost<'static, DEFAULT_MESSAGE_SIZE>,
        Dispatch<'static, 'static, DEFAULT_MESSAGE_SIZE>,
        EchoApp,
    ) {
        let (host, dispatch, app) = init_host_with_rng(OsRng);
        (host, dispatch, app)
    }

    fn init_host_with_rng<R>(
        rng: R,
    ) -> (
        CtaphidHost<'static, DEFAULT_MESSAGE_SIZE, R>,
        Dispatch<'static, 'static, DEFAULT_MESSAGE_SIZE>,
        EchoApp,
    )
    where
        R: RngCore + CryptoRng,
    {
        let channel = Box::leak(Box::new(Channel::<{ DEFAULT_MESSAGE_SIZE }>::new()));
        let (rq, rp) = channel.split().unwrap();
        let host = CtaphidHost::with_rng(rq, rng);
        let dispatch = Dispatch::new(rp);
        (host, dispatch, EchoApp)
    }

    fn take_frame_bytes<R>(
        host: &mut CtaphidHost<'static, DEFAULT_MESSAGE_SIZE, R>,
    ) -> Vec<[u8; 64]>
    where
        R: RngCore + CryptoRng,
    {
        let mut frames = Vec::new();
        while let Some(frame) = host.next_outgoing_frame() {
            frames.push(*frame.as_bytes());
        }
        frames
    }

    #[derive(Clone)]
    struct TestRng {
        values: Vec<u32>,
        index: usize,
    }

    impl TestRng {
        fn new(values: &[u32]) -> Self {
            Self {
                values: values.to_vec(),
                index: 0,
            }
        }

        fn next_value(&mut self) -> u32 {
            let value = self
                .values
                .get(self.index)
                .copied()
                .expect("test RNG exhausted");
            self.index += 1;
            value
        }
    }

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_value()
        }

        fn next_u64(&mut self) -> u64 {
            let high = self.next_value() as u64;
            let low = self.next_value() as u64;
            (high << 32) | low
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(4) {
                let value = self.next_value().to_le_bytes();
                let len = chunk.len();
                chunk.copy_from_slice(&value[..len]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for TestRng {}

    #[test]
    fn broadcast_init_skips_reserved_ids() {
        let (mut host, mut dispatch, mut app) =
            init_host_with_rng(TestRng::new(&[0, 0xffffffff, 0x1234_5678]));
        host.set_capabilities(CAPABILITY_CBOR | CAPABILITY_NMSG);

        let mut init_packet = [0u8; 64];
        init_packet[..4].copy_from_slice(&0xffffffffu32.to_be_bytes());
        init_packet[4] = Command::Init.into_u8() | 0x80;
        init_packet[5..7].copy_from_slice(&8u16.to_be_bytes());
        init_packet[7..15].copy_from_slice(&[0xAA; 8]);
        host.handle_frame(&CtapHidFrame::new(init_packet), 0);
        let mut apps: [&mut dyn App<'static, DEFAULT_MESSAGE_SIZE>; 1] = [&mut app];
        let _ = host.poll_dispatch(&mut dispatch, &mut apps);

        let frames = take_frame_bytes(&mut host);
        assert_eq!(frames.len(), 1);
        let assigned = u32::from_be_bytes(frames[0][8..12].try_into().unwrap());
        assert_eq!(assigned, 0x1234_5678);
    }

    #[test]
    fn reinit_existing_channel_reuses_cid() {
        let (mut host, mut dispatch, mut app) =
            init_host_with_rng(TestRng::new(&[0xA1A2_A3A4, 0xDEAD_BEEF]));
        host.set_capabilities(CAPABILITY_CBOR | CAPABILITY_NMSG);

        let mut broadcast_init = [0u8; 64];
        broadcast_init[..4].copy_from_slice(&0xffffffffu32.to_be_bytes());
        broadcast_init[4] = Command::Init.into_u8() | 0x80;
        broadcast_init[5..7].copy_from_slice(&8u16.to_be_bytes());
        broadcast_init[7..15].copy_from_slice(&[0x11; 8]);
        host.handle_frame(&CtapHidFrame::new(broadcast_init), 0);
        let mut apps: [&mut dyn App<'static, DEFAULT_MESSAGE_SIZE>; 1] = [&mut app];
        let _ = host.poll_dispatch(&mut dispatch, &mut apps);

        let frames = take_frame_bytes(&mut host);
        assert_eq!(frames.len(), 1);
        let assigned = u32::from_be_bytes(frames[0][8..12].try_into().unwrap());
        assert_eq!(assigned, 0xA1A2_A3A4);

        let mut reinit_packet = [0u8; 64];
        reinit_packet[..4].copy_from_slice(&assigned.to_be_bytes());
        reinit_packet[4] = Command::Init.into_u8() | 0x80;
        reinit_packet[5..7].copy_from_slice(&8u16.to_be_bytes());
        reinit_packet[7..15].copy_from_slice(&[0x22; 8]);
        host.handle_frame(&CtapHidFrame::new(reinit_packet), 10);
        let mut apps: [&mut dyn App<'static, DEFAULT_MESSAGE_SIZE>; 1] = [&mut app];
        let _ = host.poll_dispatch(&mut dispatch, &mut apps);

        let frames = take_frame_bytes(&mut host);
        assert_eq!(frames.len(), 1);
        let reused = u32::from_be_bytes(frames[0][8..12].try_into().unwrap());
        assert_eq!(reused, assigned);

        let mut second_broadcast = [0u8; 64];
        second_broadcast[..4].copy_from_slice(&0xffffffffu32.to_be_bytes());
        second_broadcast[4] = Command::Init.into_u8() | 0x80;
        second_broadcast[5..7].copy_from_slice(&8u16.to_be_bytes());
        second_broadcast[7..15].copy_from_slice(&[0x33; 8]);
        host.handle_frame(&CtapHidFrame::new(second_broadcast), 20);
        let mut apps: [&mut dyn App<'static, DEFAULT_MESSAGE_SIZE>; 1] = [&mut app];
        let _ = host.poll_dispatch(&mut dispatch, &mut apps);

        let frames = take_frame_bytes(&mut host);
        assert_eq!(frames.len(), 1);
        let next_cid = u32::from_be_bytes(frames[0][8..12].try_into().unwrap());
        assert_eq!(next_cid, 0xDEAD_BEEF);
    }

    #[test]
    fn broadcast_init_retries_on_collision() {
        let (mut host, mut dispatch, mut app) =
            init_host_with_rng(TestRng::new(&[0x0102_0304, 0x0102_0304, 0x0BAD_F00D]));
        host.set_capabilities(CAPABILITY_CBOR | CAPABILITY_NMSG);

        let mut init_packet = [0u8; 64];
        init_packet[..4].copy_from_slice(&0xffffffffu32.to_be_bytes());
        init_packet[4] = Command::Init.into_u8() | 0x80;
        init_packet[5..7].copy_from_slice(&8u16.to_be_bytes());
        init_packet[7..15].copy_from_slice(&[0x01; 8]);
        host.handle_frame(&CtapHidFrame::new(init_packet), 0);
        let mut apps: [&mut dyn App<'static, DEFAULT_MESSAGE_SIZE>; 1] = [&mut app];
        let _ = host.poll_dispatch(&mut dispatch, &mut apps);
        let frames = take_frame_bytes(&mut host);
        assert_eq!(frames.len(), 1);
        let first_cid = u32::from_be_bytes(frames[0][8..12].try_into().unwrap());
        assert_eq!(first_cid, 0x0102_0304);

        let mut second_init = [0u8; 64];
        second_init[..4].copy_from_slice(&0xffffffffu32.to_be_bytes());
        second_init[4] = Command::Init.into_u8() | 0x80;
        second_init[5..7].copy_from_slice(&8u16.to_be_bytes());
        second_init[7..15].copy_from_slice(&[0x02; 8]);
        host.handle_frame(&CtapHidFrame::new(second_init), 10);
        let mut apps: [&mut dyn App<'static, DEFAULT_MESSAGE_SIZE>; 1] = [&mut app];
        let _ = host.poll_dispatch(&mut dispatch, &mut apps);

        let frames = take_frame_bytes(&mut host);
        assert_eq!(frames.len(), 1);
        let second_cid = u32::from_be_bytes(frames[0][8..12].try_into().unwrap());
        assert_eq!(second_cid, 0x0BAD_F00D);
        assert_ne!(first_cid, second_cid);
    }

    #[test]
    fn handles_init() {
        let (mut host, mut dispatch, mut app) = init_host();
        host.set_capabilities(CAPABILITY_CBOR | CAPABILITY_NMSG);

        let mut init_packet = [0u8; 64];
        init_packet[..4].copy_from_slice(&0xffffffffu32.to_be_bytes());
        init_packet[4] = Command::Init.into_u8() | 0x80;
        init_packet[5..7].copy_from_slice(&8u16.to_be_bytes());
        init_packet[7..15].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        host.handle_frame(&CtapHidFrame::new(init_packet), 0);
        let mut apps: [&mut dyn App<'static, DEFAULT_MESSAGE_SIZE>; 1] = [&mut app];
        let _ = host.poll_dispatch(&mut dispatch, &mut apps);

        let frames = take_frame_bytes(&mut host);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][4] & 0x7f, Command::Init.into_u8());
        assert_eq!(frames[0][5..7], [0, 17]);
        assert_eq!(&frames[0][7..15], &[1, 2, 3, 4, 5, 6, 7, 8]);
        // Verify CAPABILITY_CBOR | CAPABILITY_NMSG = 0x0C
        assert_eq!(frames[0][16], CAPABILITY_CBOR | CAPABILITY_NMSG);
    }

    #[test]
    fn handles_segmented_cbor_request() {
        let (mut host, mut dispatch, mut app) = init_host();
        let channel = 0x12345678u32;
        let total_len = 80u16;
        let mut init_packet = [0u8; 64];
        init_packet[..4].copy_from_slice(&channel.to_be_bytes());
        init_packet[4] = Command::Cbor.into_u8() | 0x80;
        init_packet[5..7].copy_from_slice(&total_len.to_be_bytes());
        for i in 0..(PACKET_SIZE - 7) {
            init_packet[7 + i] = i as u8;
        }
        host.handle_frame(&CtapHidFrame::new(init_packet), 0);

        let mut cont_packet = [0u8; 64];
        cont_packet[..4].copy_from_slice(&channel.to_be_bytes());
        cont_packet[4] = 0;
        for i in 0..(PACKET_SIZE - 5) {
            cont_packet[5 + i] = (PACKET_SIZE - 7 + i) as u8;
        }
        host.handle_frame(&CtapHidFrame::new(cont_packet), 1);

        let mut apps: [&mut dyn App<'static, DEFAULT_MESSAGE_SIZE>; 1] = [&mut app];
        let _ = host.poll_dispatch(&mut dispatch, &mut apps);

        // apps echo payload, so expect two frames (init + continuation)
        let frames = take_frame_bytes(&mut host);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0][4] & 0x7f, Command::Cbor.into_u8());
        assert_eq!(u16::from_be_bytes([frames[0][5], frames[0][6]]), total_len);
        assert_eq!(frames[0][7], 0);
        assert_eq!(frames[1][4], 0);
    }

    #[test]
    fn times_out_missing_continuation() {
        let (mut host, mut dispatch, mut app) = init_host();
        let mut init_packet = [0u8; 64];
        init_packet[4] = Command::Cbor.into_u8() | 0x80;
        init_packet[5..7].copy_from_slice(&(80u16).to_be_bytes());
        host.handle_frame(&CtapHidFrame::new(init_packet), 0);

        host.handle_timeout(600);
        let mut apps: [&mut dyn App<'static, DEFAULT_MESSAGE_SIZE>; 1] = [&mut app];
        let _ = host.poll_dispatch(&mut dispatch, &mut apps);

        let frames = take_frame_bytes(&mut host);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][4] & 0x7f, Command::Error.into_u8());
        assert_eq!(frames[0][7], u8::from(AuthenticatorError::Timeout));
    }

    #[test]
    fn cancel_errors_active_request() {
        let (mut host, mut dispatch, mut app) = init_host();
        let channel = 0x1234u32;
        let mut init_packet = [0u8; 64];
        init_packet[..4].copy_from_slice(&channel.to_be_bytes());
        init_packet[4] = Command::Cbor.into_u8() | 0x80;
        init_packet[5..7].copy_from_slice(&(8u16).to_be_bytes());
        init_packet[7..15].copy_from_slice(&[0; 8]);
        host.handle_frame(&CtapHidFrame::new(init_packet), 0);

        let mut cancel_packet = [0u8; 64];
        cancel_packet[..4].copy_from_slice(&channel.to_be_bytes());
        cancel_packet[4] = Command::Cancel.into_u8() | 0x80;
        host.handle_frame(&CtapHidFrame::new(cancel_packet), 1);

        let mut apps: [&mut dyn App<'static, DEFAULT_MESSAGE_SIZE>; 1] = [&mut app];
        let _ = host.poll_dispatch(&mut dispatch, &mut apps);
        let frames = take_frame_bytes(&mut host);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][7], u8::from(AuthenticatorError::Canceled));
    }
}
