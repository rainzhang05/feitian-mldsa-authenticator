#![cfg_attr(not(target_os = "linux"), allow(unused_imports))]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("pc-hid-runner currently only supports Linux targets (needs /dev/uhid)");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    pretty_env_logger::init();

    ctrlc::set_handler(|| {
        log::info!("Received Ctrl+C, shutting down");
        std::process::exit(0);
    })
    .expect("failed to install Ctrl+C handler");

    let args = Args::parse();
    let aaguid = parse_aaguid(&args.aaguid).expect("invalid AAGUID");

    log::info!(
        "Starting HID runner with VID=0x{vid:04x} PID=0x{pid:04x}",
        vid = args.vid,
        pid = args.pid
    );

    let store = Store {
        ifs: ram_filesystem(),
        efs: ram_filesystem(),
        vfs: ram_filesystem(),
    };

    let options = Options {
        manufacturer: Some(args.manufacturer),
        product: Some(args.product),
        serial_number: Some(args.serial),
        vid: args.vid,
        pid: args.pid,
        device_class: Some(DeviceClass::hid()),
    };

    let data = AppData {
        aaguid,
        auto_user_presence: !args.manual_user_presence,
    };

    log::info!("Initializing Trussed");
    log::info!("Press Ctrl+C to exit");

    let platform = Platform::new(store);
    Builder::new(options).build::<Apps<_>>().exec(
        platform,
        data,
        Box::new(LinuxUhidTransport::new()),
    );
}

#[cfg(target_os = "linux")]
use authenticator::ctap::CtapApp;
#[cfg(target_os = "linux")]
use clap::Parser;
#[cfg(target_os = "linux")]
use clap_num::maybe_hex;
#[cfg(target_os = "linux")]
use littlefs2::{
    const_ram_storage,
    fs::{Allocation, Filesystem},
};
#[cfg(target_os = "linux")]
use littlefs2_core::{path, DynFilesystem};
#[cfg(target_os = "linux")]
use pc_hid_runner::LinuxUhidTransport;
#[cfg(target_os = "linux")]
use trussed::{
    backend::{CoreOnly, NoId},
    client::Client,
    pipe::{ServiceEndpoint, TrussedChannel},
    service::Service,
    types::{CoreContext, NoData},
};
#[cfg(target_os = "linux")]
use trussed_host_runner::{apdu_dispatch, ctaphid_dispatch};
#[cfg(target_os = "linux")]
use trussed_host_runner::{
    set_waiting, Apps as RunnerApps, Builder, Client as RunnerClient, DeviceClass, Options,
    Platform, Store, Syscall,
};

#[cfg(target_os = "linux")]
#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Args {
    /// USB product
    #[clap(
        short = 'n',
        long,
        default_value = "Feitian FIDO2 Software Authenticator (ML-DSA)"
    )]
    product: String,

    /// USB manufacturer
    #[clap(short, long, default_value = "Feitian Technologies Co., Ltd.")]
    manufacturer: String,

    /// USB serial number
    #[clap(long, default_value = "FEITIAN-PQC-001")]
    serial: String,

    /// Authenticator state file (reserved for future persistence)
    #[clap(long, default_value = "trussed-state.bin")]
    _state_file: std::path::PathBuf,

    /// USB VID
    #[clap(short, long, parse(try_from_str = maybe_hex), default_value_t = 0x1998)]
    vid: u16,

    /// USB PID
    #[clap(short, long, parse(try_from_str = maybe_hex), default_value_t = 0x0616)]
    pid: u16,

    /// Authenticator AAGUID
    #[clap(long, default_value = "4645495449414E980616525A30310000")]
    aaguid: String,

    /// Require user gestures instead of automatically satisfying presence checks
    #[clap(long)]
    manual_user_presence: bool,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct AppData {
    aaguid: [u8; 16],
    auto_user_presence: bool,
}

#[cfg(target_os = "linux")]
struct Apps<C: Client> {
    ctap: CtapApp<C>,
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
const_ram_storage!(RamStorage, 512 * 128);

#[cfg(target_os = "linux")]
fn ram_filesystem() -> &'static dyn DynFilesystem {
    let storage = Box::leak(Box::new(RamStorage::new()));
    Filesystem::format(storage).expect("failed to format RAM filesystem");
    let alloc = Box::leak(Box::new(Allocation::new()));
    let fs = Filesystem::mount(alloc, storage).expect("failed to mount RAM filesystem");
    Box::leak(Box::new(fs))
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use super::parse_aaguid;

    #[test]
    fn parses_plain_hex() {
        let input = "00112233445566778899aabbccddeeff";
        assert_eq!(
            parse_aaguid(input).unwrap(),
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF
            ]
        );
    }

    #[test]
    fn parses_hyphenated_hex() {
        let input = "00112233-4455-6677-8899-aabbccddeeff";
        assert_eq!(
            parse_aaguid(input).unwrap(),
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF
            ]
        );
    }
}
