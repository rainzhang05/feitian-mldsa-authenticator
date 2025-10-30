use std::path::PathBuf;

use authenticator::ctap::CtapApp;
use clap::{Parser, ValueEnum};
use clap_num::maybe_hex;
use littlefs2::{
    const_ram_storage,
    fs::{Allocation, Filesystem},
};
use littlefs2_core::{path, DynFilesystem};
use pc_hid_runner::{
    exec, set_waiting, Builder, Client, HidDeviceDescriptor, Options, Platform, Store, Syscall,
    CTAPHID_FRAME_LEN,
};
#[cfg(feature = "usbip-backend")]
use pc_usbip_runner::{exec as usbip_exec, Builder as UsbipBuilder};
use trussed::{
    backend::{CoreOnly, NoId},
    pipe::{ServiceEndpoint, TrussedChannel},
    service::Service,
    types::{CoreContext, NoData},
};

#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Args {
    /// HID product name
    #[clap(long, default_value = "Feitian FIDO2 Software Authenticator (ML-DSA)")]
    name: String,

    /// USB manufacturer string used by Trussed
    #[clap(long, default_value = "Feitian Technologies Co., Ltd.")]
    manufacturer: String,

    /// USB product string used by Trussed
    #[clap(long, default_value = "Feitian FIDO2 Software Authenticator (ML-DSA)")]
    product: String,

    /// USB serial number string used by Trussed
    #[clap(long, default_value = "FEITIAN-PQC-001")]
    serial: String,

    /// Vendor ID for the virtual HID device
    #[clap(long, value_parser = maybe_hex::<u32>, default_value_t = 0x096e)]
    vendor_id: u32,

    /// Product ID for the virtual HID device
    #[clap(long, value_parser = maybe_hex::<u32>, default_value_t = 0x0858)]
    product_id: u32,

    /// Version reported by the HID descriptor
    #[clap(long, value_parser = maybe_hex::<u32>, default_value_t = 0x0001)]
    version: u32,

    /// Trussed state file (reserved for future persistence)
    #[clap(long, default_value = "trussed-state.bin")]
    state_file: PathBuf,

    /// USB VID presented by Trussed (for legacy tooling)
    #[clap(short, long, value_parser = maybe_hex::<u16>, default_value_t = 0x1998)]
    vid: u16,

    /// USB PID presented by Trussed (for legacy tooling)
    #[clap(short, long, value_parser = maybe_hex::<u16>, default_value_t = 0x0616)]
    pid: u16,

    /// Authenticator AAGUID
    #[clap(long, default_value = "4645495449414E980616525A30310000")]
    aaguid: String,

    /// Require user gestures instead of automatically satisfying presence checks
    #[clap(long)]
    manual_user_presence: bool,

    /// Backend transport to use
    #[clap(long, value_enum, default_value_t = Backend::Uhid)]
    backend: Backend,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum Backend {
    Uhid,
    #[cfg(feature = "usbip-backend")]
    Usbip,
}

#[derive(Clone, Copy)]
struct AppData {
    aaguid: [u8; 16],
    auto_user_presence: bool,
}

struct Apps {
    ctap: CtapApp<Client>,
}

impl<'a> pc_hid_runner::Apps<'a, CoreOnly> for Apps {
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
        let client = Client::new(requester, syscall, None);
        let mut ctap = CtapApp::new(client, data.aaguid);
        ctap.set_auto_user_presence(data.auto_user_presence);
        ctap.set_keepalive_callback(set_waiting);
        Self { ctap }
    }

    fn with_ctaphid_apps<T, const N: usize>(
        &mut self,
        f: impl FnOnce(&mut [&mut dyn ctaphid_dispatch::app::App<'a, N>]) -> T,
    ) -> T {
        f(&mut [&mut self.ctap])
    }

    #[cfg(feature = "ccid")]
    fn with_ccid_apps<T, const N: usize>(
        &mut self,
        f: impl FnOnce(&mut [&mut dyn apdu_dispatch::app::App<N>]) -> T,
    ) -> T {
        f(&mut [])
    }
}

const_ram_storage!(RamStorage, 512 * 128);

fn ram_filesystem() -> &'static dyn DynFilesystem {
    let storage = Box::leak(Box::new(RamStorage::new()));
    Filesystem::format(storage).expect("failed to format RAM filesystem");
    let alloc = Box::leak(Box::new(Allocation::new()));
    let fs = Filesystem::mount(alloc, storage).expect("failed to mount RAM filesystem");
    Box::leak(Box::new(fs))
}

fn parse_aaguid(input: &str) -> Result<[u8; 16], String> {
    let mut cleaned = input.to_owned();
    cleaned.retain(|c| c != '-');
    if cleaned.len() != 32 {
        return Err(format!("expected 32 hex characters, got {}", cleaned.len()));
    }
    let mut out = [0u8; 16];
    for (idx, chunk) in cleaned.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(chunk).map_err(|_| "invalid UTF-8 in AAGUID".to_string())?;
        out[idx] =
            u8::from_str_radix(hex, 16).map_err(|_| format!("invalid hex at byte {}", idx))?;
    }
    Ok(out)
}

fn main() {
    pretty_env_logger::init();

    let args = Args::parse();
    let Args {
        name,
        manufacturer,
        product,
        serial,
        vendor_id,
        product_id,
        version,
        state_file: _,
        vid,
        pid,
        aaguid: aaguid_str,
        manual_user_presence,
        backend,
    } = args;

    let aaguid = parse_aaguid(&aaguid_str).expect("invalid AAGUID");

    let options = Options {
        manufacturer: Some(manufacturer.clone()),
        product: Some(product.clone()),
        serial_number: Some(serial.clone()),
        vid,
        pid,
        device_class: None,
    };

    match backend {
        Backend::Uhid => {
            let store = Store {
                ifs: ram_filesystem(),
                efs: ram_filesystem(),
                vfs: ram_filesystem(),
            };
            let platform = Platform::new(store);
            let descriptor = HidDeviceDescriptor {
                name: name.clone(),
                vendor_id,
                product_id,
                version,
                country: 0,
                feature_report: vec![0; CTAPHID_FRAME_LEN],
            };
            let runner = Builder::new(options.clone()).build::<Apps>();
            exec(
                runner,
                descriptor,
                platform,
                AppData {
                    aaguid,
                    auto_user_presence: !manual_user_presence,
                },
            )
            .expect("UHID transport exited");
        }
        #[cfg(feature = "usbip-backend")]
        Backend::Usbip => {
            let store = Store {
                ifs: ram_filesystem(),
                efs: ram_filesystem(),
                vfs: ram_filesystem(),
            };
            let platform = Platform::new(store);
            let runner = UsbipBuilder::new(options.clone()).build::<Apps>();
            usbip_exec(
                runner,
                platform,
                AppData {
                    aaguid,
                    auto_user_presence: !manual_user_presence,
                },
            )
            .expect("USB/IP transport exited");
        }
    }
}
