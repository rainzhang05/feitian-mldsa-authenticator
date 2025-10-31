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
const BUS_USB: u16 = 0x03;

const CTAPHID_REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (U2F HID Authenticator)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8 bits)
    0x95, 0x40, //   Report Count (64 bytes)
    0x81, 0x02, //   Input (Data, Variable, Absolute)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8 bits)
    0x95, 0x40, //   Report Count (64 bytes)
    0x91, 0x02, //   Output (Data, Variable, Absolute)
    0xC0, // End Collection
];
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
        write_event_blocking(fd, &mut create_event)?;

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
        write_event_blocking(self.fd.as_raw_fd(), &mut event)
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
        write_event_blocking(self.fd.as_raw_fd(), &mut event)
    }

    fn send_set_report_reply(&self, id: u32, err: u16) -> io::Result<()> {
        let mut event = raw::uhid_event::default();
        event.type_ = raw::UHID_EVENT_TYPE_SET_REPORT_REPLY;
        let reply = unsafe { &mut event.u.set_report_reply };
        reply.id = id;
        reply.err = err;
        write_event_blocking(self.fd.as_raw_fd(), &mut event)
    }

    fn destroy_blocking(&self) -> io::Result<()> {
        if self.destroyed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let mut event = raw::uhid_event::default();
        event.type_ = raw::UHID_EVENT_TYPE_DESTROY;
        write_event_blocking(self.fd.as_raw_fd(), &mut event)
    }
}

impl Drop for UhidInner {
    fn drop(&mut self) {
        let _ = self.destroy_blocking();
    }
}

fn descriptor_to_create2(descriptor: &HidDeviceDescriptor) -> io::Result<raw::uhid_create2_req> {
    if CTAPHID_REPORT_DESCRIPTOR.len() > raw::HID_MAX_DESCRIPTOR_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "report descriptor too large",
        ));
    }

    let mut req = raw::uhid_create2_req::default();
    copy_str_to_array(&descriptor.name, &mut req.name);
    req.rd_size = CTAPHID_REPORT_DESCRIPTOR.len() as u16;

    let rd_size: u16 = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(req.rd_size)) };
    log::debug!(
        "create2 rd_size={} (expected={})",
        rd_size,
        CTAPHID_REPORT_DESCRIPTOR.len() as u16
    );
    req.bus = BUS_USB;
    req.vendor = descriptor.vendor_id;
    req.product = descriptor.product_id;
    req.version = descriptor.version;
    req.country = descriptor.country;
    req.rd_data[..CTAPHID_REPORT_DESCRIPTOR.len()].copy_from_slice(&CTAPHID_REPORT_DESCRIPTOR);
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

fn write_event_blocking(fd: RawFd, event: &mut raw::uhid_event) -> io::Result<()> {
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

fn force_ctaphid_report_descriptor(event: &mut raw::uhid_event) {
    // Non-mutating validator: we only log; we never rewrite rd_data/rd_size.
    if event.type_ != raw::UHID_EVENT_TYPE_CREATE2 {
        return;
    }

    let size = unsafe {
        usize::from(core::ptr::read_unaligned(core::ptr::addr_of!(
            event.u.create2.rd_size
        )))
    };
    let expected_len = CTAPHID_REPORT_DESCRIPTOR.len();

    if size >= expected_len
        && unsafe {
            std::slice::from_raw_parts(
                core::ptr::addr_of!(event.u.create2.rd_data) as *const u8,
                expected_len,
            )
        } == CTAPHID_REPORT_DESCRIPTOR
    {
        return;
    }
    if size == 0 {
        log::warn!(
            "create2 descriptor length is zero; expected {} bytes. Not mutating.",
            expected_len
        );
    } else if size > raw::HID_MAX_DESCRIPTOR_SIZE {
        log::warn!(
            "create2 descriptor length {} exceeds HID max {}; not mutating.",
            size,
            raw::HID_MAX_DESCRIPTOR_SIZE
        );
    } else {
        log::warn!(
            "create2 descriptor does not match reference (size={}, expected={}); not mutating.",
            size,
            expected_len
        );
    }
}

fn to_io_error(err: nix::Error) -> io::Error {
    io::Error::from(err)
}

fn looks_like_ascii_hex(bytes: &[u8]) -> bool {
    let mut saw_digit = false;
    for &byte in bytes {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte.is_ascii_hexdigit() {
            saw_digit = true;
            continue;
        }
        return saw_digit;
    }
    saw_digit
}

mod raw {
    pub const UHID_DATA_MAX: usize = 4096;
    pub const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;

    pub const UHID_EVENT_TYPE_DESTROY: u32 = 1;
    pub const UHID_EVENT_TYPE_START: u32 = 2;
    pub const UHID_EVENT_TYPE_STOP: u32 = 3;
    pub const UHID_EVENT_TYPE_OPEN: u32 = 4;
    pub const UHID_EVENT_TYPE_CLOSE: u32 = 5;
    pub const UHID_EVENT_TYPE_OUTPUT: u32 = 6;
    pub const UHID_EVENT_TYPE_GET_REPORT: u32 = 9;
    pub const UHID_EVENT_TYPE_GET_REPORT_REPLY: u32 = 10;
    pub const UHID_EVENT_TYPE_CREATE2: u32 = 11;
    pub const UHID_EVENT_TYPE_INPUT2: u32 = 12;
    pub const UHID_EVENT_TYPE_SET_REPORT: u32 = 13;
    pub const UHID_EVENT_TYPE_SET_REPORT_REPLY: u32 = 14;

    pub const UHID_REPORT_TYPE_FEATURE: u8 = 0;
    pub const UHID_REPORT_TYPE_OUTPUT: u8 = 1;
    pub const UHID_REPORT_TYPE_INPUT: u8 = 2;

    pub const UHID_EVENT_SIZE: usize = core::mem::size_of::<uhid_event>();

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_create2_req {
        pub name: [u8; 128],
        pub phys: [u8; 64],
        pub uniq: [u8; 64],
        pub rd_size: u16,
        pub bus: u16,
        pub vendor: u32,
        pub product: u32,
        pub version: u32,
        pub country: u32,
        pub rd_data: [u8; HID_MAX_DESCRIPTOR_SIZE],
    }

    impl Default for uhid_create2_req {
        fn default() -> Self {
            unsafe { core::mem::zeroed() }
        }
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_input2_req {
        pub size: u16,
        pub data: [u8; UHID_DATA_MAX],
    }

    impl Default for uhid_input2_req {
        fn default() -> Self {
            unsafe { core::mem::zeroed() }
        }
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_output_req {
        pub data: [u8; UHID_DATA_MAX],
        pub size: u16,
        pub rtype: u8,
    }

    impl Default for uhid_output_req {
        fn default() -> Self {
            unsafe { core::mem::zeroed() }
        }
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_get_report_req {
        pub id: u32,
        pub rnum: u8,
        pub rtype: u8,
    }

    impl Default for uhid_get_report_req {
        fn default() -> Self {
            unsafe { core::mem::zeroed() }
        }
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_get_report_reply_req {
        pub id: u32,
        pub err: u16,
        pub size: u16,
        pub data: [u8; UHID_DATA_MAX],
    }

    impl Default for uhid_get_report_reply_req {
        fn default() -> Self {
            unsafe { core::mem::zeroed() }
        }
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_set_report_req {
        pub id: u32,
        pub rnum: u8,
        pub rtype: u8,
        pub size: u16,
        pub data: [u8; UHID_DATA_MAX],
    }

    impl Default for uhid_set_report_req {
        fn default() -> Self {
            unsafe { core::mem::zeroed() }
        }
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_set_report_reply_req {
        pub id: u32,
        pub err: u16,
    }

    impl Default for uhid_set_report_reply_req {
        fn default() -> Self {
            unsafe { core::mem::zeroed() }
        }
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_start_req {
        pub dev_flags: u64,
    }

    impl Default for uhid_start_req {
        fn default() -> Self {
            unsafe { core::mem::zeroed() }
        }
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub union uhid_event_union {
        pub create2: uhid_create2_req,
        pub input2: uhid_input2_req,
        pub output: uhid_output_req,
        pub get_report: uhid_get_report_req,
        pub get_report_reply: uhid_get_report_reply_req,
        pub set_report: uhid_set_report_req,
        pub set_report_reply: uhid_set_report_reply_req,
        pub start: uhid_start_req,
    }

    impl Default for uhid_event_union {
        fn default() -> Self {
            unsafe { core::mem::zeroed() }
        }
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_event {
        pub type_: u32,
        pub u: uhid_event_union,
    }

    impl Default for uhid_event {
        fn default() -> Self {
            Self {
                type_: 0,
                u: uhid_event_union::default(),
            }
        }
    }

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
    fn descriptor_bytes_are_copied_verbatim() {
        let descriptor = HidDeviceDescriptor::default();
        let req = descriptor_to_create2(&descriptor).expect("descriptor conversion");

        assert_eq!(
            &req.rd_data[..CTAPHID_REPORT_DESCRIPTOR.len()],
            &CTAPHID_REPORT_DESCRIPTOR
        );

        let mut event = raw::uhid_event::default();
        event.type_ = raw::UHID_EVENT_TYPE_CREATE2;
        event.u.create2 = req;

        let bytes = event_as_bytes(&event);
        let data_offset = unsafe {
            let base = (&event as *const raw::uhid_event).cast::<u8>();
            let data = event.u.create2.rd_data.as_ptr();
            data.offset_from(base) as usize
        };
        let descriptor_bytes = &bytes[data_offset..data_offset + CTAPHID_REPORT_DESCRIPTOR.len()];
        assert_eq!(descriptor_bytes, &CTAPHID_REPORT_DESCRIPTOR);
    }

    #[test]
    fn write_event_sends_raw_descriptor_bytes() {
        use nix::unistd::{close, pipe, read};

        let descriptor = HidDeviceDescriptor::default();
        let create2 = descriptor_to_create2(&descriptor).expect("descriptor conversion");
        let mut event = raw::uhid_event::default();
        event.type_ = raw::UHID_EVENT_TYPE_CREATE2;
        event.u.create2 = create2;

        let (read_fd, write_fd) = pipe().expect("pipe");
        write_event_blocking(write_fd, &mut event).expect("write_event");
        close(write_fd).ok();

        let mut buffer = [0u8; raw::UHID_EVENT_SIZE];
        let mut offset = 0;
        while offset < buffer.len() {
            let read_bytes = read(read_fd, &mut buffer[offset..]).expect("read");
            if read_bytes == 0 {
                break;
            }
            offset += read_bytes;
        }
        close(read_fd).ok();
        assert_eq!(offset, raw::UHID_EVENT_SIZE);

        let data_offset = unsafe {
            let base = (&event as *const raw::uhid_event).cast::<u8>();
            let data = event.u.create2.rd_data.as_ptr();
            data.offset_from(base) as usize
        };
        let descriptor_bytes = &buffer[data_offset..data_offset + CTAPHID_REPORT_DESCRIPTOR.len()];
        assert_eq!(descriptor_bytes, &CTAPHID_REPORT_DESCRIPTOR);
    }

    #[test]
    fn write_event_decodes_ascii_descriptor_bytes() {
        use nix::unistd::{close, pipe, read};

        let mut event = raw::uhid_event::default();
        event.type_ = raw::UHID_EVENT_TYPE_CREATE2;
        let ascii_descriptor = b"06 d0 f1 09 01 a1 01 09 20 15 00 26 ff 00 75 08 95 40 81 02 09 21 15 00 26 ff 00 75 08 95 40 91 02 c0";
        let descriptor_len = ascii_descriptor.len();
        let create2 = unsafe { &mut event.u.create2 };
        create2.rd_size = descriptor_len as u16;
        create2.rd_data[..descriptor_len].copy_from_slice(ascii_descriptor);

        let (read_fd, write_fd) = pipe().expect("pipe");
        write_event_blocking(write_fd, &mut event).expect("write_event");
        close(write_fd).ok();

        let create2 = unsafe { &event.u.create2 };
        assert_eq!(create2.rd_size as usize, CTAPHID_REPORT_DESCRIPTOR.len());
        assert_eq!(
            &create2.rd_data[..CTAPHID_REPORT_DESCRIPTOR.len()],
            &CTAPHID_REPORT_DESCRIPTOR
        );

        let mut buffer = [0u8; raw::UHID_EVENT_SIZE];
        let mut offset = 0;
        while offset < buffer.len() {
            let read_bytes = read(read_fd, &mut buffer[offset..]).expect("read");
            if read_bytes == 0 {
                break;
            }
            offset += read_bytes;
        }
        close(read_fd).ok();
        assert_eq!(offset, raw::UHID_EVENT_SIZE);

        let data_offset = unsafe {
            let base = (&event as *const raw::uhid_event).cast::<u8>();
            let data = event.u.create2.rd_data.as_ptr();
            data.offset_from(base) as usize
        };
        let descriptor_bytes = &buffer[data_offset..data_offset + CTAPHID_REPORT_DESCRIPTOR.len()];
        assert_eq!(descriptor_bytes, &CTAPHID_REPORT_DESCRIPTOR);
    }

    #[test]
    fn write_event_decodes_ascii_descriptor_with_suffix() {
        use nix::unistd::{close, pipe, read};

        let mut event = raw::uhid_event::default();
        event.type_ = raw::UHID_EVENT_TYPE_CREATE2;
        let ascii_descriptor = b"06 d0 f1 09 01 a1 01 09 20 15 00 26 ff 00 75 08 95 40 81 02 09 21 15 00 26 ff 00 75 08 95 40 91 02 c0\n  INPUT[INPUT]\n";
        let descriptor_len = ascii_descriptor.len();
        let create2 = unsafe { &mut event.u.create2 };
        create2.rd_size = descriptor_len as u16;
        create2.rd_data[..descriptor_len].copy_from_slice(ascii_descriptor);

        let (read_fd, write_fd) = pipe().expect("pipe");
        write_event_blocking(write_fd, &mut event).expect("write_event");
        close(write_fd).ok();

        let create2 = unsafe { &event.u.create2 };
        assert_eq!(create2.rd_size as usize, CTAPHID_REPORT_DESCRIPTOR.len());
        assert_eq!(
            &create2.rd_data[..CTAPHID_REPORT_DESCRIPTOR.len()],
            &CTAPHID_REPORT_DESCRIPTOR
        );

        let mut buffer = [0u8; raw::UHID_EVENT_SIZE];
        let mut offset = 0;
        while offset < buffer.len() {
            let read_bytes = read(read_fd, &mut buffer[offset..]).expect("read");
            if read_bytes == 0 {
                break;
            }
            offset += read_bytes;
        }
        close(read_fd).ok();
        assert_eq!(offset, raw::UHID_EVENT_SIZE);

        let data_offset = unsafe {
            let base = (&event as *const raw::uhid_event).cast::<u8>();
            let data = event.u.create2.rd_data.as_ptr();
            data.offset_from(base) as usize
        };
        let descriptor_bytes = &buffer[data_offset..data_offset + CTAPHID_REPORT_DESCRIPTOR.len()];
        assert_eq!(descriptor_bytes, &CTAPHID_REPORT_DESCRIPTOR);
    }

    #[test]
    fn write_event_overrides_incorrect_binary_descriptor() {
        use nix::unistd::{close, pipe, read};

        let mut event = raw::uhid_event::default();
        event.type_ = raw::UHID_EVENT_TYPE_CREATE2;
        let bogus_descriptor = [0xAAu8; CTAPHID_REPORT_DESCRIPTOR.len()];
        let create2 = unsafe { &mut event.u.create2 };
        create2.rd_size = bogus_descriptor.len() as u16;
        create2.rd_data[..bogus_descriptor.len()].copy_from_slice(&bogus_descriptor);

        let (read_fd, write_fd) = pipe().expect("pipe");
        write_event_blocking(write_fd, &mut event).expect("write_event");
        close(write_fd).ok();

        let create2 = unsafe { &event.u.create2 };
        assert_eq!(create2.rd_size as usize, CTAPHID_REPORT_DESCRIPTOR.len());
        assert_eq!(
            &create2.rd_data[..CTAPHID_REPORT_DESCRIPTOR.len()],
            &CTAPHID_REPORT_DESCRIPTOR
        );

        let mut buffer = [0u8; raw::UHID_EVENT_SIZE];
        let mut offset = 0;
        while offset < buffer.len() {
            let read_bytes = read(read_fd, &mut buffer[offset..]).expect("read");
            if read_bytes == 0 {
                break;
            }
            offset += read_bytes;
        }
        close(read_fd).ok();
        assert_eq!(offset, raw::UHID_EVENT_SIZE);

        let data_offset = unsafe {
            let base = (&event as *const raw::uhid_event).cast::<u8>();
            let data = event.u.create2.rd_data.as_ptr();
            data.offset_from(base) as usize
        };
        let descriptor_bytes = &buffer[data_offset..data_offset + CTAPHID_REPORT_DESCRIPTOR.len()];
        assert_eq!(descriptor_bytes, &CTAPHID_REPORT_DESCRIPTOR);
    }
}
