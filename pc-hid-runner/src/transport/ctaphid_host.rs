use std::{collections::VecDeque, convert::TryInto};

use crate::uhid::{CtapHidFrame, CTAPHID_FRAME_LEN};
use ctaphid_dispatch::{
    app::{App, Command, Error as AppError},
    Requester,
};
use heapless_bytes::Bytes;
use interchange::State as InterchangeState;

const PACKET_SIZE: usize = CTAPHID_FRAME_LEN;

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

pub struct CtaphidHost<'pipe, const N: usize> {
    requester: Requester<'pipe, N>,
    state: State,
    buffer: [u8; N],
    pending: VecDeque<CtapHidFrame>,
    last_channel: u32,
    implements: u8,
    version: Version,
    started_processing: bool,
    needs_keepalive: bool,
    last_millis: u64,
}

impl<'pipe, const N: usize> CtaphidHost<'pipe, N> {
    pub fn new(requester: Requester<'pipe, N>) -> Self {
        Self {
            requester,
            state: State::Idle,
            buffer: [0u8; N],
            pending: VecDeque::new(),
            last_channel: 0,
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

        self.last_channel = self.last_channel.wrapping_add(1);
        let response = Response {
            channel: request.channel,
            command: request.command,
            length: 17,
        };
        self.buffer[8..12].copy_from_slice(&self.last_channel.to_be_bytes());
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

        let payload = &self.buffer[..request.length as usize];
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
        self.pending.push_back(CtapHidFrame::new(frame));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ctaphid_dispatch::{app::App, Channel, Dispatch, DEFAULT_MESSAGE_SIZE};

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
        let channel = Box::leak(Box::new(Channel::<{ DEFAULT_MESSAGE_SIZE }>::new()));
        let (rq, rp) = channel.split().unwrap();
        let host = CtaphidHost::new(rq);
        let dispatch = Dispatch::new(rp);
        (host, dispatch, EchoApp)
    }

    fn take_frame_bytes(host: &mut CtaphidHost<'static, DEFAULT_MESSAGE_SIZE>) -> Vec<[u8; 64]> {
        let mut frames = Vec::new();
        while let Some(frame) = host.next_outgoing_frame() {
            frames.push(*frame.as_bytes());
        }
        frames
    }

    #[test]
    fn handles_init() {
        let (mut host, mut dispatch, mut app) = init_host();
        // CAPABILITY_CBOR (0x04) | CAPABILITY_NMSG (0x08) = 0x0C
        host.set_capabilities(0x0C);

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
        // Verify CAPABILITY_CBOR (0x04) | CAPABILITY_NMSG (0x08) = 0x0C
        assert_eq!(frames[0][16], 0x0C);
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
