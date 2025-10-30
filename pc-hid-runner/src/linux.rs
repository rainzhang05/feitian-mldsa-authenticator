use std::{
    any::Any,
    convert::{TryFrom, TryInto},
    fs::{self, OpenOptions},
    io::{self, ErrorKind, Read, Write},
    os::unix::{
        fs::OpenOptionsExt,
        io::{AsRawFd, RawFd},
    },
    path::PathBuf,
    ptr::NonNull,
    time::{Duration, Instant},
    vec::Vec,
};

use log::{error, info, warn};
use nix::poll::{poll, PollFd, PollFlags};
use trussed_host_runner::{
    ctaphid_dispatch::{self, Channel, Dispatch, DEFAULT_MESSAGE_SIZE},
    CtaphidDispatchRef, Options, Transport, TransportRuntime,
};
use uhid_virt::{
    Bus, CreateParams, DevFlags, InputEvent, OutputEvent, ReportType, StreamError, UHID_EVENT_SIZE,
};

use crate::ctaphid::{HidFramer, PacketWriter as CtaphidPacketWriter, PACKET_SIZE};
const REPORT_ID: u8 = 0;
const KEEPALIVE_PERIOD: Duration = Duration::from_millis(250);

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
    pipe: HidFramer<'static, { DEFAULT_MESSAGE_SIZE }>,
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
        let mut runtime = Self {
            device,
            pipe: HidFramer::new(requester),
            dispatch: Some(dispatch),
            channel: Some(NonNull::from(channel)),
            epoch: Instant::now(),
        };

        runtime.device.log_registration();

        runtime
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
                self.device.log_hidraw_nodes();
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

        let keepalive = match self.pipe.send_keepalive(&mut self.device, waiting) {
            Ok(true) => Some(KEEPALIVE_PERIOD),
            Ok(false) => None,
            Err(err) => {
                error!("failed to send keepalive: {err}");
                None
            }
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
    name: String,
    uniq: String,
    vid: u16,
    pid: u16,
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
            name: name.clone(),
            phys,
            uniq: uniq.clone(),
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
            name,
            uniq,
            vid: options.vid,
            pid: options.pid,
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

    fn send_packet(&mut self, payload: &[u8; PACKET_SIZE]) -> io::Result<()> {
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

    fn log_registration(&self) {
        info!(
            "Registered UHID device '{}' vid=0x{vid:04x} pid=0x{pid:04x} on /dev/uhid",
            self.name,
            vid = self.vid,
            pid = self.pid,
        );
        self.log_hidraw_nodes();
    }

    fn hidraw_nodes(&self) -> io::Result<Vec<PathBuf>> {
        let mut matches = Vec::new();
        let dir = match fs::read_dir("/sys/class/hidraw") {
            Ok(dir) => dir,
            Err(err) => return Err(err),
        };

        let target = format!("HID_UNIQ={}", self.uniq);
        let target_str = target.as_str();

        for entry in dir {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    warn!("failed to enumerate hidraw entry: {err}");
                    continue;
                }
            };
            let mut path = entry.path();
            path.push("device/uevent");
            let data = match fs::read_to_string(&path) {
                Ok(data) => data,
                Err(err) => {
                    warn!("failed to read {}: {err}", path.display());
                    continue;
                }
            };
            if data.lines().any(|line| line.trim() == target_str) {
                if let Some(name) = entry.file_name().to_str() {
                    matches.push(PathBuf::from("/dev").join(name));
                }
            }
        }

        Ok(matches)
    }

    fn log_hidraw_nodes(&self) {
        match self.hidraw_nodes() {
            Ok(nodes) if nodes.is_empty() => {
                info!(
                    "Waiting for hidraw node (looking for HID_UNIQ={})",
                    self.uniq
                );
            }
            Ok(nodes) => {
                let joined = nodes
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                info!("hidraw nodes available: {joined}");
            }
            Err(err) => {
                warn!("unable to enumerate hidraw nodes: {err}");
            }
        }
    }
}

impl CtaphidPacketWriter for UhidDevice {
    fn write_packet(&mut self, payload: &[u8; PACKET_SIZE]) -> io::Result<()> {
        self.send_packet(payload)
    }
}
