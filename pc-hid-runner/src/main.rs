use std::path::PathBuf;

use authenticator::ctap::PqcPolicy;
use clap::{Parser, ValueEnum};
use clap_num::maybe_hex;
use pc_hid_runner::{service, Options};
use transport_core::state::default_state_dir;

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

    /// Directory where persistent Trussed state is stored
    #[clap(long, value_parser, default_value_os_t = default_state_dir())]
    state_dir: PathBuf,

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

    /// Suppress attestation certificate material for makeCredential operations
    #[clap(long)]
    suppress_attestation: bool,

    /// Policy controlling whether PQC PIN/UV is preferred, required, or disabled
    #[clap(long, value_enum, default_value_t = PqcPolicyArg::Prefer)]
    pqc_policy: PqcPolicyArg,

    /// Backend transport to use
    #[clap(long, value_enum, default_value_t = BackendArg::Uhid)]
    backend: BackendArg,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum BackendArg {
    Uhid,
    #[cfg(feature = "usbip-backend")]
    Usbip,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum PqcPolicyArg {
    Prefer,
    ClassicOnly,
    Require,
}

impl From<PqcPolicyArg> for PqcPolicy {
    fn from(value: PqcPolicyArg) -> Self {
        match value {
            PqcPolicyArg::Prefer => PqcPolicy::PreferPqc,
            PqcPolicyArg::ClassicOnly => PqcPolicy::ClassicOnly,
            PqcPolicyArg::Require => PqcPolicy::RequirePqc,
        }
    }
}

impl BackendArg {
    fn into_backend(self) -> service::Backend {
        match self {
            BackendArg::Uhid => service::Backend::Uhid,
            #[cfg(feature = "usbip-backend")]
            BackendArg::Usbip => service::Backend::Usbip,
        }
    }
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
        state_dir,
        vid,
        pid,
        aaguid: aaguid_str,
        manual_user_presence,
        suppress_attestation,
        pqc_policy,
        backend,
    } = args;

    let aaguid = service::parse_aaguid(&aaguid_str).expect("invalid AAGUID");

    let options = Options {
        manufacturer: Some(manufacturer.clone()),
        product: Some(product.clone()),
        serial_number: Some(serial.clone()),
        vid,
        pid,
        device_class: None,
    };

    let descriptor = service::descriptor(name, vendor_id, product_id, version);
    let config = service::RunnerConfig {
        descriptor,
        options,
        state_dir: state_dir.clone(),
        aaguid,
        identity: service::IdentityStrings {
            manufacturer,
            product,
            serial,
        },
        auto_user_presence: !manual_user_presence,
        suppress_attestation,
        pqc_policy: pqc_policy.into(),
        backend: backend.into_backend(),
    };

    service::run(config).expect("transport exited unexpectedly");
}
