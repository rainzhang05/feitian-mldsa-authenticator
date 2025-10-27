//! USB/IP runner exposing the ML-DSA FIDO2 authenticator prototype.

use std::path::PathBuf;

use authenticator::ctap::CtapApp;

use clap::Parser;
use clap_num::maybe_hex;
use littlefs2::{
    const_ram_storage,
    fs::{Allocation, Filesystem},
};
use littlefs2_core::{path, DynFilesystem};
use trussed::{
    backend::{CoreOnly, NoId},
    client::Client,
    pipe::{ServiceEndpoint, TrussedChannel},
    service::Service,
    types::{CoreContext, NoData},
};
use trussed_usbip::{Platform, Store, Syscall};

#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Args {
    /// USB Name string
    #[clap(short, long, default_value = "ML-DSA Authenticator")]
    name: String,

    /// USB Manufacturer string
    #[clap(short, long, default_value = "Trussed")]
    manufacturer: String,

    /// Trussed state file
    #[clap(long, default_value = "trussed-state.bin")]
    state_file: PathBuf,

    /// USB VID id
    #[clap(short, long, parse(try_from_str=maybe_hex), default_value_t = 0x20a0)]
    vid: u16,

    /// USB PID id
    #[clap(short, long, parse(try_from_str=maybe_hex), default_value_t = 0x42b3)]
    pid: u16,
}

const AAGUID: [u8; 16] = [0x42; 16];

struct Apps<C: Client> {
    authenticator: CtapApp<C>,
}

impl<'a> trussed_usbip::Apps<'a, CoreOnly> for Apps<trussed_usbip::Client<CoreOnly>> {
    type Data = ();

    fn new(
        _service: &mut Service<Platform, CoreOnly>,
        endpoints: &mut Vec<ServiceEndpoint<'static, NoId, NoData>>,
        syscall: Syscall,
        _data: (),
    ) -> Self {
        static CHANNEL: TrussedChannel = TrussedChannel::new();
        let (requester, responder) = CHANNEL.split().unwrap();
        let context = CoreContext::new(path!("ctap").into());
        endpoints.push(ServiceEndpoint::new(responder, context, &[]));
        let client = trussed_usbip::Client::new(requester, syscall, None);
        let authenticator = CtapApp::new(client, AAGUID);
        Self { authenticator }
    }

    #[cfg(feature = "ctaphid")]
    fn with_ctaphid_apps<T, const N: usize>(
        &mut self,
        f: impl FnOnce(&mut [&mut dyn ctaphid_dispatch::app::App<'a, N>]) -> T,
    ) -> T {
        f(&mut [&mut self.authenticator])
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

fn main() {
    pretty_env_logger::init();

    let args = Args::parse();

    let store = Store {
        ifs: ram_filesystem(),
        efs: ram_filesystem(),
        vfs: ram_filesystem(),
    };
    let options = trussed_usbip::Options {
        manufacturer: Some(args.manufacturer),
        product: Some(args.name),
        serial_number: None,
        vid: args.vid,
        pid: args.pid,
    };

    log::info!("Starting ML-DSA authenticator over USB/IP");
    let platform = Platform::new(store);
    trussed_usbip::Builder::new(options)
        .build::<Apps<_>>()
        .exec(platform, ());
}
