use nix::errno::Errno;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::libc;
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
use tokio::io::unix::AsyncFd;

const DEVICE_PATH: &str = "/dev/uhid";

pub const CTAPHID_FRAME_LEN: usize = 64;
const BUS_USB: u16 = 0x03;

const CTAPHID_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (U2F HID Authenticator)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64 bytes)
    0x81, 0x02, //   Input (Data,Var,Abs)
    0x09, 0x21, //   Usage (Output Report Data)
    0x95, 0x40, //   Report Count (64 bytes)
    0x91, 0x02, //   Output (Data,Var,Abs)
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
        let async_fd = AsyncFd::new(owned)?;
        let inner = Arc::new(UhidInner::new(async_fd));

        register_signal_handler(&inner)?;

        Ok(Self { inner, descriptor })
    }

    pub async fn write_frame(&self, frame: &CtapHidFrame) -> io::Result<()> {
        self.inner.send_input_report(frame.as_bytes()).await
    }

    pub async fn read_frame(&self) -> io::Result<CtapHidFrame> {
        loop {
            let event = self.inner.read_event().await?;
            match event.type_ {
                raw::UHID_EVENT_TYPE_OUTPUT => {
                    let size = unsafe { event.u.output.size } as usize;
                    let rtype = unsafe { event.u.output.rtype };
                    if !matches!(
                        ReportType::from_raw(rtype),
                        Some(ReportType::Output) | Some(ReportType::Feature)
                    ) {
                        continue;
                    }
                    if size == CTAPHID_FRAME_LEN {
                        let mut data = [0u8; CTAPHID_FRAME_LEN];
                        unsafe {
                            data.copy_from_slice(&event.u.output.data[..CTAPHID_FRAME_LEN]);
                        }
                        return Ok(CtapHidFrame::new(data));
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
                    self.send_set_report_reply(id, status).await?;
                    if status != 0 {
                        continue;
                    }
                    if size == CTAPHID_FRAME_LEN {
                        let mut data = [0u8; CTAPHID_FRAME_LEN];
                        unsafe {
                            data.copy_from_slice(&event.u.set_report.data[..CTAPHID_FRAME_LEN]);
                        }
                        return Ok(CtapHidFrame::new(data));
                    }
                }
                raw::UHID_EVENT_TYPE_GET_REPORT => {
                    let id = unsafe { event.u.get_report.id };
                    let rtype = unsafe { event.u.get_report.rtype };
                    if ReportType::from_raw(rtype) != Some(ReportType::Feature) {
                        self.send_get_report_reply(id, Errno::EINVAL as u16, &[])
                            .await?;
                        continue;
                    }
                    self.send_get_report_reply(id, 0, &self.descriptor.feature_report)
                        .await?;
                }
                raw::UHID_EVENT_TYPE_START
                | raw::UHID_EVENT_TYPE_STOP
                | raw::UHID_EVENT_TYPE_OPEN
                | raw::UHID_EVENT_TYPE_CLOSE => {
                    // Nothing to do for lifecycle events.
                }
                _ => {}
            }
        }
    }

    pub async fn send_get_report_reply(&self, id: u32, err: u16, data: &[u8]) -> io::Result<()> {
        self.inner.send_get_report_reply(id, err, data).await
    }

    pub async fn send_set_report_reply(&self, id: u32, err: u16) -> io::Result<()> {
        self.inner.send_set_report_reply(id, err).await
    }
}

struct UhidInner {
    fd: AsyncFd<OwnedFd>,
    destroyed: AtomicBool,
}

impl UhidInner {
    fn new(fd: AsyncFd<OwnedFd>) -> Self {
        Self {
            fd,
            destroyed: AtomicBool::new(false),
        }
    }

    async fn read_event(&self) -> io::Result<raw::uhid_event> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|fd| read_event_nonblocking(fd.as_raw_fd())) {
                Ok(Ok(event)) => return Ok(event),
                Ok(Err(err)) => return Err(err),
                Err(_would_block) => continue,
            }
        }
    }

    async fn write_event(&self, event: &raw::uhid_event) -> io::Result<()> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|fd| write_event_nonblocking(fd.as_raw_fd(), event)) {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(err)) => return Err(err),
                Err(_would_block) => continue,
            }
        }
    }

    async fn send_input_report(&self, data: &[u8; CTAPHID_FRAME_LEN]) -> io::Result<()> {
        let mut event = raw::uhid_event::default();
        event.type_ = raw::UHID_EVENT_TYPE_INPUT2;
        event.u.input2.size = CTAPHID_FRAME_LEN as u16;
        unsafe {
            event.u.input2.data[..CTAPHID_FRAME_LEN].copy_from_slice(data);
        }
        self.write_event(&event).await
    }

    async fn send_get_report_reply(&self, id: u32, err: u16, data: &[u8]) -> io::Result<()> {
        if data.len() > raw::UHID_DATA_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "feature report too large",
            ));
        }
        let mut event = raw::uhid_event::default();
        event.type_ = raw::UHID_EVENT_TYPE_GET_REPORT_REPLY;
        event.u.get_report_reply.id = id;
        event.u.get_report_reply.err = err;
        event.u.get_report_reply.size = data.len() as u16;
        unsafe {
            event.u.get_report_reply.data[..data.len()].copy_from_slice(data);
        }
        self.write_event(&event).await
    }

    async fn send_set_report_reply(&self, id: u32, err: u16) -> io::Result<()> {
        let mut event = raw::uhid_event::default();
        event.type_ = raw::UHID_EVENT_TYPE_SET_REPORT_REPLY;
        event.u.set_report_reply.id = id;
        event.u.set_report_reply.err = err;
        self.write_event(&event).await
    }

    fn destroy_blocking(&self) -> io::Result<()> {
        if self.destroyed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let mut event = raw::uhid_event::default();
        event.type_ = raw::UHID_EVENT_TYPE_DESTROY;
        write_event_blocking(self.fd.get_ref().as_raw_fd(), &event)
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
    req.bus = BUS_USB;
    req.vendor = descriptor.vendor_id;
    req.product = descriptor.product_id;
    req.version = descriptor.version;
    req.country = descriptor.country;
    req.rd_data[..CTAPHID_REPORT_DESCRIPTOR.len()].copy_from_slice(CTAPHID_REPORT_DESCRIPTOR);
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

fn write_event_nonblocking(fd: RawFd, event: &raw::uhid_event) -> io::Result<()> {
    let mut offset = 0;
    let bytes = event_as_bytes(event);
    while offset < bytes.len() {
        match write(fd, &bytes[offset..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")),
            Ok(n) => offset += n,
            Err(Errno::EINTR) => continue,
            Err(Errno::EAGAIN) => return Err(io::ErrorKind::WouldBlock.into()),
            Err(err) => return Err(to_io_error(err.into())),
        }
    }
    Ok(())
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
