use nix::errno::Errno;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::libc;
use nix::poll::{poll, PollFd, PollFlags};
use nix::unistd::{read, write};
use serde::{Deserialize, Serialize};
use signal_hook::iterator::Signals;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const DEVICE_PATH: &str = "/dev/uhid";

pub const CTAPHID_FRAME_LEN: usize = 64;
const BUS_USB: u16 = raw::BUS_USB;

// HID report descriptor describing a CTAPHID/FIDO2 authenticator. Keeping it as a raw
// byte array avoids any accidental ASCII serialization before it is submitted to the
// kernel via UHID_CREATE2.
const CTAPHID_REPORT_DESCRIPTOR: [u8; 47] = [
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
    0x02, 0x09, 0x22, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0xB1, 0x02, 0xC0,
];
const FIDO_HID_REPORT_DESCRIPTOR_LENGTH: usize = CTAPHID_REPORT_DESCRIPTOR.len();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HidDeviceDescriptor {
    pub name: String,
    pub vendor_id: u32,
    pub product_id: u32,
    pub version: u32,
    pub country: u32,
    pub feature_report: Vec<u8>,
}

impl Default for HidDeviceDescriptor {
    fn default() -> Self {
        Self {
            name: "Virtual FIDO Authenticator".to_string(),
            vendor_id: 0x096e,
            product_id: 0x0858,
            version: 0x0001,
            country: 0,
            feature_report: vec![0; CTAPHID_FRAME_LEN],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtapHidFrame(pub [u8; CTAPHID_FRAME_LEN]);

impl CtapHidFrame {
    pub fn new(data: [u8; CTAPHID_FRAME_LEN]) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8; CTAPHID_FRAME_LEN] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportType {
    Feature,
    Output,
    Input,
}

impl ReportType {
    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            raw::UHID_REPORT_TYPE_FEATURE => Some(Self::Feature),
            raw::UHID_REPORT_TYPE_OUTPUT => Some(Self::Output),
            raw::UHID_REPORT_TYPE_INPUT => Some(Self::Input),
            _ => None,
        }
    }
}

fn frame_from_report_slice(slice: &[u8]) -> Option<CtapHidFrame> {
    match slice.len() {
        CTAPHID_FRAME_LEN => {
            let mut data = [0u8; CTAPHID_FRAME_LEN];
            data.copy_from_slice(&slice[..CTAPHID_FRAME_LEN]);
            Some(CtapHidFrame::new(data))
        }
        len if len == CTAPHID_FRAME_LEN + 1 && slice.first().copied() == Some(0) => {
            let mut data = [0u8; CTAPHID_FRAME_LEN];
            data.copy_from_slice(&slice[1..1 + CTAPHID_FRAME_LEN]);
            Some(CtapHidFrame::new(data))
        }
        _ => None,
    }
}

pub struct UhidDevice {
    inner: Arc<UhidInner>,
    descriptor: HidDeviceDescriptor,
}

impl UhidDevice {
    pub fn new(descriptor: HidDeviceDescriptor) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(DEVICE_PATH)?;
        let fd = file.as_raw_fd();

        let create2 = descriptor_to_create2(&descriptor)?;
        let mut create_event = raw::uhid_event::default();
        create_event.type_ = raw::UHID_EVENT_TYPE_CREATE2;
        create_event.u.create2 = create2;
        write_event_blocking(fd, &create_event)?;

        let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(to_io_error)?;
        let mut oflags = OFlag::from_bits_truncate(flags);
        oflags.insert(OFlag::O_NONBLOCK);
        fcntl(fd, FcntlArg::F_SETFL(oflags)).map_err(to_io_error)?;

        let owned = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };
        let inner = Arc::new(UhidInner::new(owned));

        register_signal_handler(&inner)?;

        Ok(Self { inner, descriptor })
    }

    pub fn try_read_frame(&self) -> io::Result<Option<CtapHidFrame>> {
        loop {
            match self.inner.try_read_event()? {
                None => return Ok(None),
                Some(event) => match event.type_ {
                    raw::UHID_EVENT_TYPE_OUTPUT => {
                        let size = unsafe { event.u.output.size } as usize;
                        let rtype = unsafe { event.u.output.rtype };
                        if !matches!(
                            ReportType::from_raw(rtype),
                            Some(ReportType::Output) | Some(ReportType::Feature)
                        ) {
                            continue;
                        }
                        if let Some(frame) =
                            unsafe { frame_from_report_slice(&event.u.output.data[..size]) }
                        {
                            return Ok(Some(frame));
                        }
                    }
                    raw::UHID_EVENT_TYPE_SET_REPORT => {
                        let size = unsafe { event.u.set_report.size } as usize;
                        let id = unsafe { event.u.set_report.id };
                        let rtype = unsafe { event.u.set_report.rtype };
                        let status = if matches!(
                            ReportType::from_raw(rtype),
                            Some(ReportType::Output) | Some(ReportType::Feature)
                        ) {
                            0
                        } else {
                            Errno::EINVAL as u16
                        };
                        self.inner.send_set_report_reply(id, status)?;
                        if status != 0 {
                            continue;
                        }
                        if let Some(frame) =
                            unsafe { frame_from_report_slice(&event.u.set_report.data[..size]) }
                        {
                            return Ok(Some(frame));
                        }
                    }
                    raw::UHID_EVENT_TYPE_GET_REPORT => {
                        let id = unsafe { event.u.get_report.id };
                        let rtype = unsafe { event.u.get_report.rtype };
                        if ReportType::from_raw(rtype) != Some(ReportType::Feature) {
                            self.inner
                                .send_get_report_reply(id, Errno::EINVAL as u16, &[])?;
                            continue;
                        }
                        self.inner
                            .send_get_report_reply(id, 0, &self.descriptor.feature_report)?;
                    }
                    raw::UHID_EVENT_TYPE_START
                    | raw::UHID_EVENT_TYPE_STOP
                    | raw::UHID_EVENT_TYPE_OPEN
                    | raw::UHID_EVENT_TYPE_CLOSE => {}
                    _ => {}
                },
            }
        }
    }

    pub fn write_frame(&self, frame: &CtapHidFrame) -> io::Result<()> {
        self.inner.send_input_report(frame.as_bytes())
    }

    pub fn wait(&self, timeout: Option<Duration>) -> io::Result<bool> {
        self.inner.wait(timeout)
    }
}

struct UhidInner {
    fd: OwnedFd,
    destroyed: AtomicBool,
}

impl UhidInner {
    fn new(fd: OwnedFd) -> Self {
        Self {
            fd,
            destroyed: AtomicBool::new(false),
        }
    }

    fn try_read_event(&self) -> io::Result<Option<raw::uhid_event>> {
        match read_event_nonblocking(self.fd.as_raw_fd()) {
            Ok(event) => Ok(Some(event)),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn wait(&self, timeout: Option<Duration>) -> io::Result<bool> {
        let mut fds = [PollFd::new(&self.fd, PollFlags::POLLIN)];
        let timeout_ms = timeout
            .map(|d| d.as_millis().min(i32::MAX as u128) as i32)
            .unwrap_or(-1);
        loop {
            match poll(&mut fds, timeout_ms) {
                Ok(ready) => return Ok(ready > 0),
                Err(Errno::EINTR) => continue,
                Err(err) => return Err(to_io_error(err.into())),
            }
        }
    }

    fn send_input_report(&self, data: &[u8; CTAPHID_FRAME_LEN]) -> io::Result<()> {
        let mut event = raw::uhid_event::default();
        event.type_ = raw::UHID_EVENT_TYPE_INPUT2;
        let input = unsafe { &mut event.u.input2 };
        input.size = CTAPHID_FRAME_LEN as u16;
        input.data[..CTAPHID_FRAME_LEN].copy_from_slice(data);
        write_event_blocking(self.fd.as_raw_fd(), &event)
    }

    fn send_get_report_reply(&self, id: u32, err: u16, data: &[u8]) -> io::Result<()> {
        if data.len() > raw::UHID_DATA_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "feature report too large",
            ));
        }
        let mut event = raw::uhid_event::default();
        event.type_ = raw::UHID_EVENT_TYPE_GET_REPORT_REPLY;
        let reply = unsafe { &mut event.u.get_report_reply };
        reply.id = id;
        reply.err = err;
        reply.size = data.len() as u16;
        reply.data[..data.len()].copy_from_slice(data);
        write_event_blocking(self.fd.as_raw_fd(), &event)
    }

    fn send_set_report_reply(&self, id: u32, err: u16) -> io::Result<()> {
        let mut event = raw::uhid_event::default();
        event.type_ = raw::UHID_EVENT_TYPE_SET_REPORT_REPLY;
        let reply = unsafe { &mut event.u.set_report_reply };
        reply.id = id;
        reply.err = err;
        write_event_blocking(self.fd.as_raw_fd(), &event)
    }

    fn destroy_blocking(&self) -> io::Result<()> {
        if self.destroyed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let mut event = raw::uhid_event::default();
        event.type_ = raw::UHID_EVENT_TYPE_DESTROY;
        write_event_blocking(self.fd.as_raw_fd(), &event)
    }
}

impl Drop for UhidInner {
    fn drop(&mut self) {
        let _ = self.destroy_blocking();
    }
}

fn descriptor_to_create2(descriptor: &HidDeviceDescriptor) -> io::Result<raw::uhid_create2_req> {
    if FIDO_HID_REPORT_DESCRIPTOR_LENGTH > raw::HID_MAX_DESCRIPTOR_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "report descriptor too large",
        ));
    }

    let mut req = raw::uhid_create2_req::default();
    copy_str_to_array(&descriptor.name, &mut req.name);
    req.rd_size = FIDO_HID_REPORT_DESCRIPTOR_LENGTH as u16;
    req.bus = BUS_USB;
    req.vendor = descriptor.vendor_id;
    req.product = descriptor.product_id;
    req.version = descriptor.version;
    req.country = descriptor.country;
    req.rd_data[..FIDO_HID_REPORT_DESCRIPTOR_LENGTH].copy_from_slice(&CTAPHID_REPORT_DESCRIPTOR);
    Ok(req)
}

fn copy_str_to_array(value: &str, dest: &mut [u8]) {
    let mut bytes = value.as_bytes();
    if bytes.len() >= dest.len() {
        bytes = &bytes[..dest.len() - 1];
    }
    dest[..bytes.len()].copy_from_slice(bytes);
    dest[bytes.len()] = 0;
}

fn register_signal_handler(inner: &Arc<UhidInner>) -> io::Result<()> {
    let mut signals = Signals::new([libc::SIGINT, libc::SIGTERM])?;
    let weak = Arc::downgrade(inner);
    std::thread::spawn(move || {
        for _ in signals.forever() {
            if let Some(device) = weak.upgrade() {
                let _ = device.destroy_blocking();
            } else {
                break;
            }
        }
    });
    Ok(())
}

fn write_event_blocking(fd: RawFd, event: &raw::uhid_event) -> io::Result<()> {
    loop {
        match write(fd, event_as_bytes(event)) {
            Ok(n) if n == raw::UHID_EVENT_SIZE => return Ok(()),
            Ok(_) => return Err(io::Error::new(io::ErrorKind::Other, "short write")),
            Err(Errno::EINTR) => continue,
            Err(Errno::EAGAIN) => {
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(err) => return Err(to_io_error(err.into())),
        }
    }
}

fn read_event_nonblocking(fd: RawFd) -> io::Result<raw::uhid_event> {
    let mut buffer = [0u8; raw::UHID_EVENT_SIZE];
    let mut offset = 0;
    while offset < buffer.len() {
        match read(fd, &mut buffer[offset..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof")),
            Ok(n) => offset += n,
            Err(Errno::EINTR) => continue,
            Err(Errno::EAGAIN) => return Err(io::ErrorKind::WouldBlock.into()),
            Err(err) => return Err(to_io_error(err.into())),
        }
    }
    Ok(raw::event_from_bytes(&buffer))
}

fn event_as_bytes(event: &raw::uhid_event) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts(
            (event as *const raw::uhid_event) as *const u8,
            raw::UHID_EVENT_SIZE,
        )
    }
}

fn to_io_error(err: nix::Error) -> io::Error {
    io::Error::from(err)
}

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code
)]
mod raw_bindings {
    include!(concat!(env!("OUT_DIR"), "/uhid_bindings.rs"));
}

mod raw {
    use super::raw_bindings;

    pub use raw_bindings::uhid_create2_req;
    pub use raw_bindings::uhid_event;

    pub const BUS_USB: u16 = raw_bindings::BUS_USB as u16;
    pub const HID_MAX_DESCRIPTOR_SIZE: usize = raw_bindings::HID_MAX_DESCRIPTOR_SIZE as usize;
    pub const UHID_DATA_MAX: usize = raw_bindings::UHID_DATA_MAX as usize;

    pub const UHID_EVENT_TYPE_DESTROY: u32 = raw_bindings::uhid_event_type_UHID_DESTROY as u32;
    pub const UHID_EVENT_TYPE_START: u32 = raw_bindings::uhid_event_type_UHID_START as u32;
    pub const UHID_EVENT_TYPE_STOP: u32 = raw_bindings::uhid_event_type_UHID_STOP as u32;
    pub const UHID_EVENT_TYPE_OPEN: u32 = raw_bindings::uhid_event_type_UHID_OPEN as u32;
    pub const UHID_EVENT_TYPE_CLOSE: u32 = raw_bindings::uhid_event_type_UHID_CLOSE as u32;
    pub const UHID_EVENT_TYPE_OUTPUT: u32 = raw_bindings::uhid_event_type_UHID_OUTPUT as u32;
    pub const UHID_EVENT_TYPE_GET_REPORT: u32 =
        raw_bindings::uhid_event_type_UHID_GET_REPORT as u32;
    pub const UHID_EVENT_TYPE_GET_REPORT_REPLY: u32 =
        raw_bindings::uhid_event_type_UHID_GET_REPORT_REPLY as u32;
    pub const UHID_EVENT_TYPE_CREATE2: u32 = raw_bindings::uhid_event_type_UHID_CREATE2 as u32;
    pub const UHID_EVENT_TYPE_INPUT2: u32 = raw_bindings::uhid_event_type_UHID_INPUT2 as u32;
    pub const UHID_EVENT_TYPE_SET_REPORT: u32 =
        raw_bindings::uhid_event_type_UHID_SET_REPORT as u32;
    pub const UHID_EVENT_TYPE_SET_REPORT_REPLY: u32 =
        raw_bindings::uhid_event_type_UHID_SET_REPORT_REPLY as u32;

    pub const UHID_REPORT_TYPE_FEATURE: u8 =
        raw_bindings::uhid_report_type_UHID_FEATURE_REPORT as u8;
    pub const UHID_REPORT_TYPE_OUTPUT: u8 = raw_bindings::uhid_report_type_UHID_OUTPUT_REPORT as u8;
    pub const UHID_REPORT_TYPE_INPUT: u8 = raw_bindings::uhid_report_type_UHID_INPUT_REPORT as u8;

    pub const UHID_EVENT_SIZE: usize = core::mem::size_of::<uhid_event>();

    pub fn event_from_bytes(bytes: &[u8; UHID_EVENT_SIZE]) -> uhid_event {
        unsafe { core::ptr::read(bytes.as_ptr() as *const uhid_event) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ctaphid_dispatch::app::Command;

    fn init_frame() -> [u8; CTAPHID_FRAME_LEN] {
        let mut frame = [0u8; CTAPHID_FRAME_LEN];
        frame[..4].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
        frame[4] = Command::Init.into_u8() | 0x80;
        frame[5..7].copy_from_slice(&(8u16).to_be_bytes());
        frame[7..15].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        frame
    }

    fn ping_frame() -> [u8; CTAPHID_FRAME_LEN] {
        let mut frame = [0u8; CTAPHID_FRAME_LEN];
        frame[..4].copy_from_slice(&0x0102_0304u32.to_be_bytes());
        frame[4] = Command::Ping.into_u8() | 0x80;
        frame[5..7].copy_from_slice(&(16u16).to_be_bytes());
        for (idx, byte) in frame[7..23].iter_mut().enumerate() {
            *byte = idx as u8;
        }
        frame
    }

    fn with_leading_zero(frame: [u8; CTAPHID_FRAME_LEN]) -> [u8; CTAPHID_FRAME_LEN + 1] {
        let mut out = [0u8; CTAPHID_FRAME_LEN + 1];
        out[1..].copy_from_slice(&frame);
        out
    }

    #[test]
    fn accepts_prefixed_init_report() {
        let frame = init_frame();
        let prefixed = with_leading_zero(frame);

        let parsed = frame_from_report_slice(&prefixed).expect("frame not parsed");
        assert_eq!(parsed.as_bytes(), &init_frame());

        let parsed_without_prefix = frame_from_report_slice(&frame).expect("64-byte frame");
        assert_eq!(parsed_without_prefix.as_bytes(), &init_frame());
    }

    #[test]
    fn accepts_prefixed_ping_report() {
        let frame = ping_frame();
        let prefixed = with_leading_zero(frame);

        let parsed = frame_from_report_slice(&prefixed).expect("frame not parsed");
        assert_eq!(parsed.as_bytes(), &ping_frame());
    }

    #[test]
    fn rejects_nonzero_report_id_prefix() {
        let mut prefixed = with_leading_zero(init_frame());
        prefixed[0] = 1;

        assert!(frame_from_report_slice(&prefixed).is_none());
    }

    #[test]
    fn ctaphid_descriptor_matches_expected_bytes() {
        let descriptor = super::CTAPHID_REPORT_DESCRIPTOR;
        let expected: [u8; super::FIDO_HID_REPORT_DESCRIPTOR_LENGTH] = [
            0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00,
            0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75,
            0x08, 0x95, 0x40, 0x91, 0x02, 0x09, 0x22, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08,
            0x95, 0x40, 0xB1, 0x02, 0xC0,
        ];
        assert_eq!(descriptor, expected);
    }

    #[test]
    fn create_request_contains_binary_descriptor() {
        let descriptor = super::HidDeviceDescriptor::default();
        let request = super::descriptor_to_create2(&descriptor).expect("create request");

        assert_eq!(
            request.rd_size as usize,
            super::FIDO_HID_REPORT_DESCRIPTOR_LENGTH
        );
        assert_eq!(
            &request.rd_data[..super::FIDO_HID_REPORT_DESCRIPTOR_LENGTH],
            &super::CTAPHID_REPORT_DESCRIPTOR,
        );
    }
}
