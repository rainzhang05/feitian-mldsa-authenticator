use std::{
    io,
    path::{Path, PathBuf},
};

use authenticator::ctap::{CtapApp, PqcPolicy};
#[cfg(feature = "usbip-backend")]
use pc_usbip_runner::{exec as usbip_exec, Builder as UsbipBuilder};
use transport_core::state::{IdentityConfig, PersistentStore};
use transport_core::{set_waiting, Apps as TrussedApps, Builder, Options, Platform, Syscall};
use trussed::{
    backend::{CoreOnly, NoId},
    pipe::{ServiceEndpoint, TrussedChannel},
    service::Service,
    types::{CoreContext, NoData},
};

use crate::{exec, HidDeviceDescriptor, CTAPHID_FRAME_LEN};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Uhid,
    #[cfg(feature = "usbip-backend")]
    Usbip,
}

#[derive(Clone)]
pub struct IdentityStrings {
    pub manufacturer: String,
    pub product: String,
    pub serial: String,
}

pub struct RunnerConfig {
    pub descriptor: HidDeviceDescriptor,
    pub options: Options,
    pub state_dir: PathBuf,
    pub aaguid: [u8; 16],
    pub identity: IdentityStrings,
    pub auto_user_presence: bool,
    pub suppress_attestation: bool,
    pub pqc_policy: PqcPolicy,
    pub backend: Backend,
}

#[derive(Clone, Copy)]
pub struct AppData {
    pub aaguid: [u8; 16],
    pub auto_user_presence: bool,
    pub suppress_attestation: bool,
    pub pqc_policy: PqcPolicy,
}

pub struct Apps {
    ctap: CtapApp<crate::Client>,
}

impl<'a> TrussedApps<'a, CoreOnly> for Apps {
    type Data = AppData;

    fn new(
        _service: &mut Service<Platform, CoreOnly>,
        endpoints: &mut Vec<ServiceEndpoint<'static, NoId, NoData>>,
        syscall: Syscall,
        data: Self::Data,
    ) -> Self {
        static CHANNEL: TrussedChannel = TrussedChannel::new();
        let (requester, responder) = CHANNEL.split().expect("Trussed channel split");
        let context = CoreContext::new(littlefs2::path!("authenticator").into());
        endpoints.push(ServiceEndpoint::new(responder, context, &[]));
        let client = crate::Client::new(requester, syscall, None);
        let mut ctap = CtapApp::new(client, data.aaguid);
        ctap.set_auto_user_presence(data.auto_user_presence);
        ctap.suppress_attestation(data.suppress_attestation);
        ctap.set_pqc_policy(data.pqc_policy);
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

pub fn run(config: RunnerConfig) -> io::Result<()> {
    let RunnerConfig {
        descriptor,
        options,
        state_dir,
        aaguid,
        identity,
        auto_user_presence,
        suppress_attestation,
        pqc_policy,
        backend,
    } = config;

    let mut persistent = PersistentStore::new(&state_dir)?;
    persistent.initialize_identity(IdentityConfig {
        aaguid,
        manufacturer: &identity.manufacturer,
        product: &identity.product,
        serial: &identity.serial,
    })?;
    let store = persistent.store();
    let platform = Platform::new(store);
    let data = AppData {
        aaguid,
        auto_user_presence,
        suppress_attestation,
        pqc_policy,
    };

    match backend {
        Backend::Uhid => {
            let runner = Builder::new(options).build::<Apps>();
            exec(runner, descriptor, platform, data)
        }
        #[cfg(feature = "usbip-backend")]
        Backend::Usbip => {
            let runner = UsbipBuilder::new(options).build::<Apps>();
            usbip_exec(runner, platform, data)
        }
    }
}

pub fn descriptor(
    name: String,
    vendor_id: u32,
    product_id: u32,
    version: u32,
) -> HidDeviceDescriptor {
    HidDeviceDescriptor {
        name,
        vendor_id,
        product_id,
        version,
        country: 0,
        feature_report: vec![0; CTAPHID_FRAME_LEN],
    }
}

pub fn parse_aaguid(input: &str) -> Result<[u8; 16], String> {
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

pub fn default_identity() -> IdentityStrings {
    IdentityStrings {
        manufacturer: "Feitian Technologies Co., Ltd.".to_string(),
        product: "Feitian FIDO2 Software Authenticator (ML-DSA)".to_string(),
        serial: "FEITIAN-PQC-001".to_string(),
    }
}

pub fn ensure_state_dir(path: &Path) -> io::Result<()> {
    transport_core::state::ensure_state_dir(path)
}
