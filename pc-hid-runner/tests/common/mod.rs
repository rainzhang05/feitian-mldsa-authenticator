#![cfg(target_os = "linux")]

use std::{
    fs::OpenOptions,
    io,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use authenticator::ctap::CtapApp;
use hidapi::{HidApi, HidDevice};
use littlefs2::{
    const_ram_storage,
    fs::{Allocation, Filesystem},
};
use littlefs2_core::{path, DynFilesystem};
use rand::{rngs::OsRng, RngCore};
use trussed::{
    backend::{CoreOnly, NoId},
    client::Client,
    pipe::{ServiceEndpoint, TrussedChannel},
    service::Service,
    types::{CoreContext, NoData},
};
use trussed_host_runner::{
    set_waiting, shutdown_channel, Apps as RunnerApps, Builder, Client as RunnerClient,
    DeviceClass, Options, Platform, Store, Syscall,
};

use pc_hid_runner::LinuxUhidTransport;

pub const VID: u16 = 0x1998;
pub const PID: u16 = 0x0616;
const AAGUID_HEX: &str = "4645495449414E980616525A30310000";

#[derive(Clone, Copy)]
struct AppData {
    aaguid: [u8; 16],
    auto_user_presence: bool,
}

struct Apps<C: Client> {
    ctap: CtapApp<C>,
}

impl<'a> RunnerApps<'a, CoreOnly> for Apps<RunnerClient<CoreOnly>> {
    type Data = AppData;

    fn new(
        _service: &mut Service<Platform, CoreOnly>,
        endpoints: &mut Vec<ServiceEndpoint<'static, NoId, NoData>>,
        syscall: Syscall,
        data: Self::Data,
    ) -> Self {
        static CHANNEL: TrussedChannel = TrussedChannel::new();
        let (requester, responder) = CHANNEL.split().expect("Trussed channel split");
        let context = CoreContext::new(path!("authenticator").into());
        endpoints.push(ServiceEndpoint::new(responder, context, &[]));
        let client = RunnerClient::new(requester, syscall, None);
        let mut ctap = CtapApp::new(client, data.aaguid);
        ctap.set_auto_user_presence(data.auto_user_presence);
        ctap.set_keepalive_callback(set_waiting);
        Self { ctap }
    }

    #[cfg(feature = "ctaphid")]
    fn with_ctaphid_apps<T, const N: usize>(
        &mut self,
        f: impl FnOnce(&mut [&mut dyn trussed_host_runner::ctaphid_dispatch::app::App<'a, N>]) -> T,
    ) -> T {
        f(&mut [&mut self.ctap])
    }

    #[cfg(feature = "ccid")]
    fn with_ccid_apps<T, const N: usize>(
        &mut self,
        f: impl FnOnce(&mut [&mut dyn trussed_host_runner::apdu_dispatch::app::App<N>]) -> T,
    ) -> T {
        f(&mut [])
    }
}

const_ram_storage!(RamStorage, 512 * 128);

fn ram_filesystem() -> Result<&'static dyn DynFilesystem> {
    let storage = Box::leak(Box::new(RamStorage::new()));
    Filesystem::format(storage).context("format RAM filesystem")?;
    let alloc = Box::leak(Box::new(Allocation::new()));
    let fs = Filesystem::mount(alloc, storage).context("mount RAM filesystem")?;
    Ok(Box::leak(Box::new(fs)))
}

fn parse_aaguid(input: &str) -> Result<[u8; 16]> {
    let mut cleaned = input.to_string();
    cleaned.retain(|c| c != '-');
    if cleaned.len() != 32 {
        return Err(anyhow!("invalid AAGUID length: {}", cleaned.len()));
    }
    let mut out = [0u8; 16];
    for (chunk, slot) in cleaned.as_bytes().chunks(2).zip(out.iter_mut()) {
        let hi = (chunk[0] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow!("invalid hex"))?;
        let lo = (chunk[1] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow!("invalid hex"))?;
        *slot = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

pub fn ensure_uhid_access() -> io::Result<()> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/uhid")?;
    Ok(())
}

pub struct TestRunner {
    serial: String,
    signal: trussed_host_runner::ShutdownSignal,
    handle: Option<thread::JoinHandle<()>>,
}

impl TestRunner {
    pub fn start() -> Result<Self> {
        ensure_uhid_access().context("/dev/uhid not accessible")?;

        let store = Store {
            ifs: ram_filesystem()?,
            efs: ram_filesystem()?,
            vfs: ram_filesystem()?,
        };

        let mut serial_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut serial_bytes);
        let serial = format!("TEST-HID-{:016x}", u64::from_be_bytes(serial_bytes));

        let options = Options {
            manufacturer: Some("Test Manufacturer".to_string()),
            product: Some("Trussed HID Test Authenticator".to_string()),
            serial_number: Some(serial.clone()),
            vid: VID,
            pid: PID,
            device_class: Some(DeviceClass::hid()),
        };

        let aaguid = parse_aaguid(AAGUID_HEX)?;
        let data = AppData {
            aaguid,
            auto_user_presence: true,
        };

        let (signal, listener) = shutdown_channel();
        let platform = Platform::new(store);

        let handle = thread::spawn(move || {
            let runner = Builder::new(options).build::<Apps<_>>();
            runner.run_with_shutdown(
                platform,
                data,
                Box::new(LinuxUhidTransport::new()),
                listener,
            );
        });

        Ok(Self {
            serial,
            signal,
            handle: Some(handle),
        })
    }

    pub fn serial(&self) -> &str {
        &self.serial
    }

    pub fn wait_for_device(&self, timeout: Duration) -> Result<HidDevice> {
        let api = HidApi::new().context("create hidapi instance")?;
        let deadline = Instant::now() + timeout;
        loop {
            api.refresh_devices().ok();
            for device in api.device_list() {
                if device.vendor_id() == VID
                    && device.product_id() == PID
                    && device
                        .serial_number()
                        .map(|s| s == self.serial)
                        .unwrap_or(false)
                {
                    return device.open_device(&api).context("open hidapi device");
                }
            }
            if Instant::now() >= deadline {
                return Err(anyhow!("timed out waiting for HID device"));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn wait_for_hidraw_nodes(&self, timeout: Duration) -> Result<Vec<PathBuf>> {
        let deadline = Instant::now() + timeout;
        loop {
            match hidraw_nodes(&self.serial) {
                Ok(nodes) if !nodes.is_empty() => return Ok(nodes),
                Ok(_) => {}
                Err(err) => return Err(err.into()),
            }
            if Instant::now() >= deadline {
                return Err(anyhow!("timed out waiting for hidraw nodes"));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for TestRunner {
    fn drop(&mut self) {
        self.signal.request_shutdown();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn hidraw_nodes(serial: &str) -> io::Result<Vec<PathBuf>> {
    let mut matches = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/hidraw") else {
        return Ok(matches);
    };
    let needle = format!("HID_UNIQ={}", serial);
    for entry in entries.flatten() {
        let mut path = entry.path();
        path.push("device/uevent");
        let Ok(data) = std::fs::read_to_string(&path) else {
            continue;
        };
        if data.lines().any(|line| line.trim() == needle) {
            if let Some(name) = entry.file_name().to_str() {
                matches.push(PathBuf::from("/dev").join(name));
            }
        }
    }
    Ok(matches)
}
