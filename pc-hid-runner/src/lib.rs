pub mod cli;
pub mod permissions;
pub mod service;
pub mod transport;
pub mod uhid;

use std::{
    io,
    time::{Duration, Instant},
};

use ctaphid_dispatch::{self, Channel, DEFAULT_MESSAGE_SIZE};
use transport::ctaphid_host::{CtaphidHost, Version};
pub use transport_core::{
    set_waiting, waiting_for_user_presence, Apps, Builder, Client, Options, Platform, Runner,
    Store, Syscall, Timeout, Transport,
};
use trussed::backend::Dispatch;
pub use uhid::{CtapHidFrame, HidDeviceDescriptor, ReportType, UhidDevice, CTAPHID_FRAME_LEN};

// CTAPHID capability flags (CTAP spec section 11.2.9.1.3)
pub const CAPABILITY_CBOR: u8 = 0x04; // Implements CTAPHID_CBOR
pub const CAPABILITY_NMSG: u8 = 0x08; // Does NOT implement CTAPHID_MSG

pub struct UhidTransport<'pipe, 'interrupt> {
    device: UhidDevice,
    host: CtaphidHost<'pipe, { DEFAULT_MESSAGE_SIZE }>,
    dispatch: ctaphid_dispatch::Dispatch<'pipe, 'interrupt, { DEFAULT_MESSAGE_SIZE }>,
    epoch: Instant,
}

impl<'pipe, 'interrupt> UhidTransport<'pipe, 'interrupt> {
    pub fn new(
        device: UhidDevice,
        host: CtaphidHost<'pipe, { DEFAULT_MESSAGE_SIZE }>,
        dispatch: ctaphid_dispatch::Dispatch<'pipe, 'interrupt, { DEFAULT_MESSAGE_SIZE }>,
    ) -> Self {
        Self {
            device,
            host,
            dispatch,
            epoch: Instant::now(),
        }
    }

    fn flush_pending(&mut self) -> io::Result<bool> {
        let mut wrote = false;
        while let Some(frame) = self.host.next_outgoing_frame() {
            self.device.write_frame(&frame)?;
            wrote = true;
        }
        Ok(wrote)
    }
}

impl<'interrupt, D> Transport<'interrupt, D> for UhidTransport<'_, 'interrupt>
where
    D: Dispatch,
{
    fn poll<A: Apps<'interrupt, D>>(&mut self, apps: &mut A) -> io::Result<bool> {
        let mut did_work = false;
        loop {
            match self.device.try_read_frame()? {
                Some(frame) => {
                    let elapsed = self.epoch.elapsed().as_millis() as u64;
                    self.host.handle_frame(&frame, elapsed);
                    did_work = true;
                }
                None => break,
            }
        }

        did_work |=
            apps.with_ctaphid_apps(|apps| self.host.poll_dispatch(&mut self.dispatch, apps));

        if self.host.take_started_processing() {
            did_work = true;
        }

        if self.host.has_pending_frames() {
            did_work |= self.flush_pending()?;
        }

        Ok(did_work)
    }

    fn send(&mut self, waiting_for_user: bool) -> io::Result<bool> {
        let elapsed = self.epoch.elapsed().as_millis() as u64;
        self.host.handle_timeout(elapsed);
        let mut did_work = false;
        if self.host.send_keepalive(waiting_for_user) {
            did_work |= self.flush_pending()?;
        }
        if self.host.has_pending_frames() {
            did_work |= self.flush_pending()?;
        }
        Ok(did_work)
    }

    fn wait(&mut self) -> io::Result<()> {
        let _ = self.device.wait(Some(Duration::from_millis(10)))?;
        Ok(())
    }
}

pub fn exec<'interrupt, D, A>(
    runner: Runner<D, A>,
    descriptor: HidDeviceDescriptor,
    platform: Platform,
    data: A::Data,
) -> io::Result<()>
where
    D: Dispatch,
    D::BackendId: Send + Sync,
    D::Context: Send + Sync,
    A: Apps<'interrupt, D>,
{
    let descriptor_clone = descriptor.clone();
    let device = UhidDevice::new(descriptor)?;
    if let Ok(nodes) = permissions::hidraw_nodes_for_descriptor(&descriptor_clone) {
        for node in nodes {
            let mode = node.mode & 0o777;
            if mode & 0o007 != 0 {
                log::warn!(
                    "{} is world-accessible (mode {:o}); install the bundled udev rule or tighten permissions",
                    node.path.display(),
                    mode
                );
            }
        }
    }
    let channel: Channel<{ DEFAULT_MESSAGE_SIZE }> = Channel::new();
    let (requester, responder) = channel
        .split()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "failed to split CTAPHID channel"))?;
    let mut host = CtaphidHost::new(requester);
    host.set_version(Version {
        major: 2,
        minor: 1,
        build: 0,
    });
    // Setting both capability bits prevents hosts from probing CTAPHID_MSG and enables proper CTAP2 detection
    host.set_capabilities(CAPABILITY_CBOR | CAPABILITY_NMSG);
    let dispatch = ctaphid_dispatch::Dispatch::new(responder);
    let transport = UhidTransport::new(device, host, dispatch);
    runner.exec(platform, data, transport)
}
