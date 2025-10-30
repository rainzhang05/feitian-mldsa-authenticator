use std::{
    fs::{self, OpenOptions},
    io,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, Instant},
};

use authenticator::ctap::PqcPolicy;
use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_num::maybe_hex;
use daemonize::Daemonize;
use nix::{
    errno::Errno,
    sys::signal::{self, Signal},
    unistd::Pid,
};
use pc_hid_runner::{service, Options};
use transport_core::state::default_state_dir;

#[derive(Parser, Debug)]
#[clap(
    about = "Feitian ML-DSA authenticator service controller",
    version,
    author
)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start the authenticator service
    Start(StartCommand),
    /// Stop a running authenticator service
    Stop(StateArgs),
    /// Show service status
    Status(StateArgs),
}

#[derive(Args, Debug, Clone)]
struct StartCommand {
    #[clap(flatten)]
    device: DeviceArgs,
    #[clap(flatten)]
    state: StateArgs,
    /// Run in the foreground (useful for systemd integration)
    #[clap(long)]
    foreground: bool,
}

#[derive(Args, Debug, Clone)]
struct StateArgs {
    /// Directory where persistent Trussed state and pid files are stored
    #[clap(long, value_parser, default_value_os_t = default_state_dir())]
    state_dir: PathBuf,
}

#[derive(Args, Debug, Clone)]
struct DeviceArgs {
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

impl StateArgs {
    fn pid_path(&self) -> PathBuf {
        self.state_dir.join("authenticator.pid")
    }
}

impl StartCommand {
    fn to_runner_config(&self) -> Result<service::RunnerConfig, String> {
        let aaguid = service::parse_aaguid(&self.device.aaguid)?;
        let options = Options {
            manufacturer: Some(self.device.manufacturer.clone()),
            product: Some(self.device.product.clone()),
            serial_number: Some(self.device.serial.clone()),
            vid: self.device.vid,
            pid: self.device.pid,
            device_class: None,
        };
        let descriptor = service::descriptor(
            self.device.name.clone(),
            self.device.vendor_id,
            self.device.product_id,
            self.device.version,
        );
        Ok(service::RunnerConfig {
            descriptor,
            options,
            state_dir: self.state.state_dir.clone(),
            aaguid,
            identity: service::IdentityStrings {
                manufacturer: self.device.manufacturer.clone(),
                product: self.device.product.clone(),
                serial: self.device.serial.clone(),
            },
            auto_user_presence: !self.device.manual_user_presence,
            suppress_attestation: self.device.suppress_attestation,
            pqc_policy: self.device.pqc_policy.into(),
            backend: self.device.backend.into_backend(),
        })
    }
}

fn read_pid(path: &Path) -> io::Result<Option<Pid>> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let trimmed = contents.trim();
            if trimmed.is_empty() {
                fs::remove_file(path).ok();
                return Ok(None);
            }
            match trimmed.parse::<i32>() {
                Ok(pid) => Ok(Some(Pid::from_raw(pid))),
                Err(_) => {
                    fs::remove_file(path).ok();
                    Ok(None)
                }
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn process_running(pid: Pid) -> bool {
    match signal::kill(pid, None) {
        Ok(_) => true,
        Err(Errno::ESRCH) => false,
        Err(_) => true,
    }
}

fn run_service(config: service::RunnerConfig) -> io::Result<()> {
    let _ = pretty_env_logger::try_init();
    service::run(config)
}

fn start(cmd: StartCommand) -> io::Result<()> {
    let state_dir = cmd.state.state_dir.clone();
    service::ensure_state_dir(&state_dir)?;
    let pid_path = cmd.state.pid_path();
    if let Some(pid) = read_pid(&pid_path)? {
        if process_running(pid) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("authenticator already running (pid {})", pid),
            ));
        }
        fs::remove_file(&pid_path).ok();
    }

    let config = cmd
        .to_runner_config()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    if cmd.foreground {
        fs::write(&pid_path, format!("{}\n", process::id()))?;
        let result = run_service(config);
        fs::remove_file(&pid_path).ok();
        return result;
    }

    let log_path = state_dir.join("authenticator.log");
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)?;
    let stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)?;

    let daemon = Daemonize::new()
        .pid_file(&pid_path)
        .stdout(stdout)
        .stderr(stderr)
        .exit_action(|| println!("Authenticator daemonizing..."));

    daemon
        .start()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

    let result = run_service(config);
    fs::remove_file(&pid_path).ok();
    result
}

fn stop(state: StateArgs) -> io::Result<()> {
    let pid_path = state.pid_path();
    match read_pid(&pid_path)? {
        Some(pid) => {
            if process_running(pid) {
                signal::kill(pid, Signal::SIGTERM)
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
                let deadline = Instant::now() + Duration::from_secs(5);
                while process_running(pid) && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(200));
                }
                if process_running(pid) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for authenticator to stop",
                    ));
                }
            }
            fs::remove_file(&pid_path).ok();
            println!("Authenticator stopped");
            Ok(())
        }
        None => {
            println!("Authenticator is not running");
            Ok(())
        }
    }
}

fn status(state: StateArgs) -> io::Result<()> {
    let pid_path = state.pid_path();
    match read_pid(&pid_path)? {
        Some(pid) if process_running(pid) => {
            println!("Authenticator running (pid {})", pid);
        }
        Some(_) => {
            fs::remove_file(&pid_path).ok();
            println!("Authenticator is not running");
        }
        None => println!("Authenticator is not running"),
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Start(cmd) => start(cmd),
        Command::Stop(state) => stop(state),
        Command::Status(state) => status(state),
    }
}
