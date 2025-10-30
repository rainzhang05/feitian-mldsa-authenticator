#![allow(clippy::too_many_arguments)]

use trussed_host_runner::Transport;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
pub struct LinuxUhidTransport;

#[cfg(not(target_os = "linux"))]
impl LinuxUhidTransport {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(target_os = "linux"))]
impl Transport for LinuxUhidTransport {
    fn register(
        &mut self,
        _options: &trussed_host_runner::Options,
    ) -> Box<dyn trussed_host_runner::TransportRuntime> {
        panic!("LinuxUhidTransport is only supported on Linux targets");
    }

    fn poll(&mut self, _runtime: &mut dyn trussed_host_runner::TransportRuntime) -> bool {
        panic!("LinuxUhidTransport is only supported on Linux targets");
    }

    #[cfg(feature = "ctaphid")]
    fn ctaphid_keepalive(
        &mut self,
        _runtime: &mut dyn trussed_host_runner::TransportRuntime,
        _waiting: bool,
    ) -> (Option<std::time::Duration>, Option<std::time::Duration>) {
        panic!("LinuxUhidTransport is only supported on Linux targets");
    }

    #[cfg(feature = "ccid")]
    fn ccid_keepalive(
        &mut self,
        _runtime: &mut dyn trussed_host_runner::TransportRuntime,
    ) -> (Option<std::time::Duration>, Option<std::time::Duration>) {
        panic!("LinuxUhidTransport is only supported on Linux targets");
    }
}
