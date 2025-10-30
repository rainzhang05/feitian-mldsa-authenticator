use std::{
    any::Any,
    convert::{TryFrom, TryInto},
    fs::OpenOptions,
    io::{self, ErrorKind, Read, Write},
    os::unix::{
        fs::OpenOptionsExt,
        io::{AsRawFd, RawFd},
    },
    ptr::NonNull,
    time::{Duration, Instant},
    vec::Vec,
};

use heapless_bytes::Bytes;
use log::{error, info, warn};
use nix::poll::{poll, PollFd, PollFlags};
use trussed_host_runner::{
    ctaphid_dispatch::{self, app::Command, Channel, Dispatch, DEFAULT_MESSAGE_SIZE},
    CtaphidDispatchRef, Options, Transport, TransportRuntime,
};
use uhid_virt::{
    Bus, CreateParams, DevFlags, InputEvent, OutputEvent, ReportType, StreamError, UHID_EVENT_SIZE,
};

const PACKET_SIZE: usize = 64;
const REPORT_ID: u8 = 0;
const KEEPALIVE_PERIOD: Duration = Duration::from_millis(250);
const VERSION_MAJOR: u8 = 0;
const VERSION_MINOR: u8 = 1;
const VERSION_BUILD: u8 = 0;

const FIDO_HID_REPORT_DESCRIPTOR: [u8; 34] = [
    0x06,
    0xD0,
    0xF1, // Usage Page (FIDO Alliance)
    0x09,
    0x01, // Usage (FIDO Device)
    0xA1,
    0x01, // Collection (Application)
    0x09,
    0x03, // Usage (Input report)
    0x15,
    0x00, // Logical Minimum (0)
    0x26,
    0xFF,
    0x00, // Logical Maximum (255)
    0x75,
    0x08, // Report Size (8 bits)
    0x95,
    PACKET_SIZE as u8, // Report Count (64 fields)
    0x81,
    0x08, // Input (Data, Variable, Absolute)
    0x09,
    0x04, // Usage (Output report)
    0x15,
    0x00, // Logical Minimum (0)
    0x26,
    0xFF,
    0x00, // Logical Maximum (255)
    0x75,
    0x08, // Report Size (8 bits)
    0x95,
    PACKET_SIZE as u8, // Report Count (64 fields)
    0x91,
    0x08, // Output (Data, Variable, Absolute)
    0xC0, // End Collection
];

pub struct LinuxUhidTransport;

impl LinuxUhidTransport {
    pub fn new() -> Self {
        Self
    }
}

impl Transport for LinuxUhidTransport {
    fn register(&mut self, options: &Options) -> Box<dyn TransportRuntime> {
        let channel = Box::new(Channel::<{ DEFAULT_MESSAGE_SIZE }>::new());
        let channel_ref: &'static Channel<{ DEFAULT_MESSAGE_SIZE }> = Box::leak(channel);
        let (requester, responder) = channel_ref.split().expect("channel split");
        let dispatch = Dispatch::new(responder);

        let device = UhidDevice::create(options).expect("failed to create UHID device");

        Box::new(LinuxUhidRuntime::new(
            device,
            channel_ref,
            requester,
            dispatch,
        ))
    }

    fn poll(&mut self, runtime: &mut dyn TransportRuntime) -> bool {
        runtime
            .as_any_mut()
            .downcast_mut::<LinuxUhidRuntime>()
            .expect("linux uhid runtime downcast")
            .poll()
    }

    #[cfg(feature = "ctaphid")]
    fn ctaphid_keepalive(
        &mut self,
        runtime: &mut dyn TransportRuntime,
        waiting: bool,
    ) -> (Option<Duration>, Option<Duration>) {
        runtime
            .as_any_mut()
            .downcast_mut::<LinuxUhidRuntime>()
            .expect("linux uhid runtime downcast")
            .ctaphid_keepalive(waiting)
    }

    #[cfg(feature = "ccid")]
    fn ccid_keepalive(
        &mut self,
        _runtime: &mut dyn TransportRuntime,
    ) -> (Option<Duration>, Option<Duration>) {
        (None, None)
    }
}

struct LinuxUhidRuntime {
    device: UhidDevice,
    pipe: HidPipe,
    dispatch: Option<Dispatch<'static, 'static, { DEFAULT_MESSAGE_SIZE }>>,
    channel: Option<NonNull<Channel<{ DEFAULT_MESSAGE_SIZE }>>>,
    epoch: Instant,
}

impl LinuxUhidRuntime {
    fn new(
        device: UhidDevice,
        channel: &'static Channel<{ DEFAULT_MESSAGE_SIZE }>,
        requester: ctaphid_dispatch::Requester<'static, { DEFAULT_MESSAGE_SIZE }>,
        dispatch: Dispatch<'static, 'static, { DEFAULT_MESSAGE_SIZE }>,
    ) -> Self {
        Self {
            device,
            pipe: HidPipe::new(requester),
            dispatch: Some(dispatch),
            channel: Some(NonNull::from(channel)),
            epoch: Instant::now(),
        }
    }

    fn elapsed_millis(&self) -> u32 {
        let elapsed = self.epoch.elapsed();
        elapsed.as_millis().min(u32::MAX as u128) as u32
    }

    fn poll(&mut self) -> bool {
        let now = self.elapsed_millis();
        self.pipe.check_timeout(&mut self.device, now);

        let mut handled = false;
        let mut poll_fd = [PollFd::new(
            self.device.raw_fd(),
            PollFlags::POLLIN | PollFlags::POLLOUT,
        )];

        if let Ok(events) = poll(&mut poll_fd, 0) {
            if events > 0 {
                if let Some(flags) = poll_fd[0].revents() {
                    if flags.contains(PollFlags::POLLIN) {
                        handled |= self.drain_kernel_events();
                    }

                    if flags.contains(PollFlags::POLLOUT) {
                        handled |= self.pipe.maybe_write_packet(&mut self.device);
                    }
                }
            }
        }

        self.pipe.handle_response(&mut self.device);
        handled |= self.pipe.maybe_write_packet(&mut self.device);

        handled
    }

    fn drain_kernel_events(&mut self) -> bool {
        let mut handled = false;
        loop {
            match self.device.read_event() {
                Ok(Some(event)) => {
                    handled = true;
                    self.handle_event(event);
                }
                Ok(None) => break,
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(err) => {
                    error!("error reading /dev/uhid: {err}");
                    break;
                }
            }
        }
        handled
    }

    fn handle_event(&mut self, event: OutputEvent) {
        match event {
            OutputEvent::Start { dev_flags } => {
                self.device.update_flags(&dev_flags);
                self.pipe.reset();
            }
            OutputEvent::Stop => {
                info!("UHID device stopped");
                self.pipe.reset();
            }
            OutputEvent::Open => {
                info!("UHID device opened");
            }
            OutputEvent::Close => {
                info!("UHID device closed");
                self.pipe.reset();
            }
            OutputEvent::Output { data } => {
                if let Some(packet) = self.device.decode_packet(&data) {
                    self.pipe
                        .handle_packet(&mut self.device, &packet, self.elapsed_millis());
                } else {
                    warn!("ignoring malformed HID output frame ({} bytes)", data.len());
                }
            }
            OutputEvent::GetReport {
                id,
                report_number,
                report_type,
            } => {
                info!("UHID GET_REPORT id={id} report={report_number} type={report_type:?}");
                let _ = self
                    .device
                    .write_get_report_reply(id, 0, Vec::new())
                    .map_err(|err| error!("failed to reply to GET_REPORT: {err}"));
            }
            OutputEvent::SetReport {
                id,
                report_number,
                report_type,
                data,
            } => {
                info!(
                    "UHID SET_REPORT id={id} report={report_number} type={report_type:?} len={}",
                    data.len()
                );
                let _ = self
                    .device
                    .write_set_report_reply(id, 0)
                    .map_err(|err| error!("failed to ack SET_REPORT: {err}"));
            }
        }
    }

    #[cfg(feature = "ctaphid")]
    fn ctaphid_keepalive(&mut self, waiting: bool) -> (Option<Duration>, Option<Duration>) {
        let started = if self.pipe.did_start_processing() {
            Some(KEEPALIVE_PERIOD)
        } else {
            None
        };

        let keepalive = if self
            .pipe
            .send_keepalive(&mut self.device, waiting)
            .unwrap_or(false)
        {
            Some(KEEPALIVE_PERIOD)
        } else {
            None
        };

        (started, keepalive)
    }
}

impl TransportRuntime for LinuxUhidRuntime {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    #[cfg(feature = "ctaphid")]
    fn ctaphid_dispatch<'interrupt>(&mut self) -> Option<CtaphidDispatchRef<'_, 'interrupt>> {
        self.dispatch
            .as_mut()
            .map(|dispatch| CtaphidDispatchRef::new(dispatch))
    }

    #[cfg(feature = "ccid")]
    fn ccid_dispatch(&mut self) -> Option<trussed_host_runner::CcidDispatchRef<'_>> {
        None
    }
}

impl Drop for LinuxUhidRuntime {
    fn drop(&mut self) {
        self.dispatch.take();
        if let Some(ptr) = self.channel.take() {
            unsafe {
                drop(Box::from_raw(ptr.as_ptr()));
            }
        }
        if let Err(err) = self.device.destroy() {
            error!("failed to destroy UHID device: {err}");
        }
    }
}

struct UhidDevice {
    file: std::fs::File,
    input_numbered: bool,
    output_numbered: bool,
    feature_numbered: bool,
}

impl UhidDevice {
    fn create(options: &Options) -> io::Result<Self> {
        let mut open = OpenOptions::new();
        open.read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK);
        let mut file = open.open("/dev/uhid")?;

        let name = options
            .product
            .clone()
            .unwrap_or_else(|| "Trussed HID Authenticator".to_string());
        let phys = options
            .manufacturer
            .clone()
            .unwrap_or_else(|| "trussed-host".to_string());
        let uniq = options
            .serial_number
            .clone()
            .unwrap_or_else(|| "000000000000".to_string());

        let params = CreateParams {
            name,
            phys,
            uniq,
            bus: Bus::USB,
            vendor: options.vid.into(),
            product: options.pid.into(),
            version: 0,
            country: 0,
            rd_data: FIDO_HID_REPORT_DESCRIPTOR.to_vec(),
        };

        let event: [u8; UHID_EVENT_SIZE] = InputEvent::Create(params).into();
        file.write_all(&event)?;

        Ok(Self {
            file,
            input_numbered: false,
            output_numbered: false,
            feature_numbered: false,
        })
    }

    fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    fn update_flags(&mut self, flags: &[DevFlags]) {
        self.input_numbered = flags.contains(&DevFlags::InputReportsNumbered);
        self.output_numbered = flags.contains(&DevFlags::OutputReportsNumbered);
        self.feature_numbered = flags.contains(&DevFlags::FeatureReportsNumbered);
    }

    fn read_event(&mut self) -> io::Result<Option<OutputEvent>> {
        let mut buffer = [0u8; UHID_EVENT_SIZE];
        match self.file.read_exact(&mut buffer) {
            Ok(()) => match OutputEvent::try_from(buffer) {
                Ok(event) => Ok(Some(event)),
                Err(StreamError::UnknownEventType(kind)) => {
                    warn!("unknown UHID event type {kind}");
                    Ok(None)
                }
                Err(StreamError::Io(err)) => Err(err),
            },
            Err(err) if err.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(err) if err.kind() == ErrorKind::Interrupted => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn write_event(&mut self, event: InputEvent<'_>) -> io::Result<()> {
        let raw: [u8; UHID_EVENT_SIZE] = event.into();
        self.file.write_all(&raw)
    }

    fn write_packet(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut report = [0u8; PACKET_SIZE + 1];
        let mut offset = 0;
        if self.input_numbered {
            report[0] = REPORT_ID;
            offset = 1;
        }
        report[offset..offset + PACKET_SIZE].copy_from_slice(payload);
        self.write_event(InputEvent::Input {
            data: &report[..offset + PACKET_SIZE],
        })
    }

    fn write_get_report_reply(&mut self, id: u32, err: u16, data: Vec<u8>) -> io::Result<()> {
        self.write_event(InputEvent::GetReportReply { id, err, data })
    }

    fn write_set_report_reply(&mut self, id: u32, err: u16) -> io::Result<()> {
        self.write_event(InputEvent::SetReportReply { id, err })
    }

    fn decode_packet(&self, data: &[u8]) -> Option<[u8; PACKET_SIZE]> {
        let expected = if self.output_numbered {
            PACKET_SIZE + 1
        } else {
            PACKET_SIZE
        };
        if data.len() < expected {
            return None;
        }
        let offset = if self.output_numbered {
            if data[0] != REPORT_ID {
                warn!("unexpected report id {}", data[0]);
            }
            1
        } else {
            0
        };
        let mut packet = [0u8; PACKET_SIZE];
        packet.copy_from_slice(&data[offset..offset + PACKET_SIZE]);
        Some(packet)
    }

    fn destroy(&mut self) -> io::Result<()> {
        self.write_event(InputEvent::Destroy)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Request {
    channel: u32,
    command: Command,
    length: u16,
    timestamp: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Response {
    channel: u32,
    command: Command,
    length: u16,
}

impl Response {
    fn from_request(request: Request, len: usize) -> Self {
        Self {
            channel: request.channel,
            command: request.command,
            length: len as u16,
        }
    }

    fn error_from_request(request: Request) -> Self {
        Self {
            channel: request.channel,
            command: Command::Error,
            length: 1,
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

struct HidPipe {
    requester: ctaphid_dispatch::Requester<'static, { DEFAULT_MESSAGE_SIZE }>,
    buffer: [u8; DEFAULT_MESSAGE_SIZE],
    state: State,
    last_channel: u32,
    started_processing: bool,
    needs_keepalive: bool,
    last_millis: u32,
    implements: u8,
}

impl HidPipe {
    fn new(requester: ctaphid_dispatch::Requester<'static, { DEFAULT_MESSAGE_SIZE }>) -> Self {
        Self {
            requester,
            buffer: [0u8; DEFAULT_MESSAGE_SIZE],
            state: State::Idle,
            last_channel: 0,
            started_processing: false,
            needs_keepalive: false,
            last_millis: 0,
            implements: 0x05,
        }
    }

    fn reset(&mut self) {
        self.state = State::Idle;
        self.started_processing = false;
        self.needs_keepalive = false;
        let _ = self.requester.cancel();
    }

    fn handle_packet(&mut self, device: &mut UhidDevice, packet: &[u8; PACKET_SIZE], now: u32) {
        let channel = u32::from_be_bytes(packet[..4].try_into().unwrap());
        let is_initialization = (packet[4] >> 7) != 0;

        if is_initialization {
            let command_byte = packet[4] & !0x80;
            let command = match Command::try_from(command_byte) {
                Ok(command) => command,
                Err(_) => {
                    self.start_sending_error_on_channel(
                        device,
                        channel,
                        AuthenticatorError::InvalidCommand,
                    );
                    return;
                }
            };

            let length = u16::from_be_bytes([packet[5], packet[6]]);
            if length as usize > self.buffer.len() {
                self.start_sending_error_on_channel(
                    device,
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
                self.dispatch_request(device, request);
            } else {
                self.state = State::Receiving((request, MessageState::default()));
            }
        } else {
            match &mut self.state {
                State::Receiving((request, state)) => {
                    if packet[4] != state.next_sequence {
                        self.start_sending_error(device, *request, AuthenticatorError::InvalidSeq);
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
                        self.dispatch_request(device, *request);
                    }
                }
                _ => {
                    warn!("unexpected continuation packet");
                }
            }
        }
    }

    fn dispatch_request(&mut self, device: &mut UhidDevice, request: Request) {
        match request.command {
            Command::Init => {
                if request.length != 8 {
                    self.start_sending_error(device, request, AuthenticatorError::InvalidLength);
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
                self.start_sending(device, response);
            }
            Command::Ping => {
                let response = Response::from_request(request, request.length as usize);
                self.start_sending(device, response);
            }
            Command::Cancel => {
                self.cancel_ongoing_activity();
            }
            _ => {
                self.needs_keepalive = matches!(request.command, Command::Cbor);
                let _ = self.requester.take_response();

                match self.requester.request((
                    request.command,
                    Bytes::from_slice(&self.buffer[..request.length as usize]).unwrap(),
                )) {
                    Ok(()) => {
                        self.state = State::WaitingOnAuthenticator(request);
                        self.started_processing = true;
                    }
                    Err(_) => {
                        self.send_error_now(device, request, AuthenticatorError::ChannelBusy);
                    }
                }
            }
        }
    }

    fn cancel_ongoing_activity(&mut self) {
        if let State::WaitingOnAuthenticator(_) = self.state {
            let _ = self.requester.cancel();
        }
        self.state = State::Idle;
    }

    fn did_start_processing(&mut self) -> bool {
        if self.started_processing {
            self.started_processing = false;
            true
        } else {
            false
        }
    }

    fn send_keepalive(
        &mut self,
        device: &mut UhidDevice,
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

            device.write_packet(&packet)?;
            return Ok(true);
        }

        Ok(false)
    }

    fn check_timeout(&mut self, device: &mut UhidDevice, now: u32) {
        let last = self.last_millis;
        self.last_millis = now;
        if let State::Receiving((request, _)) = &mut self.state {
            if now.wrapping_sub(request.timestamp) > 550 {
                let request = *request;
                self.start_sending_error(device, request, AuthenticatorError::Timeout);
                self.state = State::Idle;
            } else if now.wrapping_sub(last) > 200 {
                request.timestamp = now;
            }
        }
    }

    fn handle_response(&mut self, device: &mut UhidDevice) {
        if let State::WaitingOnAuthenticator(request) = self.state {
            if let Ok(response) = self.requester.response() {
                match &response.0 {
                    Err(ctaphid_dispatch::app::Error::InvalidCommand) => {
                        self.start_sending_error(
                            device,
                            request,
                            AuthenticatorError::InvalidCommand,
                        );
                    }
                    Err(ctaphid_dispatch::app::Error::InvalidLength) => {
                        self.start_sending_error(
                            device,
                            request,
                            AuthenticatorError::InvalidLength,
                        );
                    }
                    Err(ctaphid_dispatch::app::Error::NoResponse) => {}
                    Ok(message) => {
                        if message.len() > self.buffer.len() {
                            self.start_sending_error(
                                device,
                                request,
                                AuthenticatorError::InvalidLength,
                            );
                        } else {
                            self.buffer[..message.len()].copy_from_slice(message);
                            let response = Response::from_request(request, message.len());
                            self.start_sending(device, response);
                        }
                    }
                }
            }
        }
    }

    fn start_sending(&mut self, device: &mut UhidDevice, response: Response) {
        self.state = State::WaitingToSend(response);
        let _ = self.maybe_write_packet(device);
    }

    fn start_sending_error(
        &mut self,
        device: &mut UhidDevice,
        request: Request,
        error: AuthenticatorError,
    ) {
        self.start_sending_error_on_channel(device, request.channel, error);
    }

    fn start_sending_error_on_channel(
        &mut self,
        device: &mut UhidDevice,
        channel: u32,
        error: AuthenticatorError,
    ) {
        self.buffer[0] = error.into();
        let response = Response::error_on_channel(channel);
        self.start_sending(device, response);
    }

    fn send_error_now(
        &mut self,
        device: &mut UhidDevice,
        request: Request,
        error: AuthenticatorError,
    ) {
        let prev_state = std::mem::replace(&mut self.state, State::Idle);
        let prev = self.buffer[0];
        self.buffer[0] = error.into();
        let response = Response::error_from_request(request);
        self.start_sending(device, response);
        let _ = self.maybe_write_packet(device);
        self.state = prev_state;
        self.buffer[0] = prev;
    }

    fn maybe_write_packet(&mut self, device: &mut UhidDevice) -> bool {
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

                match device.write_packet(&packet) {
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
                        error!("failed to write UHID packet: {err}");
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

                match device.write_packet(&packet) {
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
                        error!("failed to write UHID packet: {err}");
                        false
                    }
                }
            }
            _ => false,
        }
    }
}
