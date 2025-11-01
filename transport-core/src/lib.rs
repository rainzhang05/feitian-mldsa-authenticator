use std::{
    io,
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender},
    },
    thread,
};

pub mod ctap;
pub mod logging;

use littlefs2_core::DynFilesystem;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng as _;
use trussed::{
    backend::{CoreOnly, Dispatch},
    pipe::ServiceEndpoint,
    platform,
    service::Service,
    store,
    virt::UserInterface,
    ClientImplementation,
};

static IS_WAITING: AtomicBool = AtomicBool::new(false);

pub fn set_waiting(waiting: bool) {
    IS_WAITING.store(waiting, Ordering::Relaxed)
}

pub fn waiting_for_user_presence() -> bool {
    IS_WAITING.load(Ordering::Relaxed)
}

pub type Client<D = CoreOnly> = ClientImplementation<'static, Syscall, D>;

pub mod state;

#[derive(Clone, Copy, Debug)]
pub struct DeviceClass {
    pub class: u8,
    pub sub_class: u8,
    pub protocol: u8,
}

impl DeviceClass {
    pub const fn new(class: u8, sub_class: u8, protocol: u8) -> Self {
        Self {
            class,
            sub_class,
            protocol,
        }
    }

    pub const fn per_interface() -> Self {
        Self::new(0x00, 0x00, 0x00)
    }

    pub const fn hid() -> Self {
        Self::new(0x03, 0x00, 0x00)
    }

    pub const fn composite() -> Self {
        Self::new(0xEF, 0x02, 0x01)
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial_number: Option<String>,
    pub vid: u16,
    pub pid: u16,
    pub device_class: Option<DeviceClass>,
}

impl Options {
    pub fn resolved_device_class(&self, ctaphid_enabled: bool, ccid_enabled: bool) -> DeviceClass {
        self.device_class
            .unwrap_or_else(|| infer_device_class(ctaphid_enabled, ccid_enabled))
    }
}

pub trait Apps<'interrupt, D: Dispatch> {
    type Data;

    fn new(
        service: &mut Service<Platform, D>,
        endpoints: &mut Vec<ServiceEndpoint<'static, D::BackendId, D::Context>>,
        syscall: Syscall,
        data: Self::Data,
    ) -> Self;

    #[cfg(feature = "ctaphid")]
    fn with_ctaphid_apps<T, const N: usize>(
        &mut self,
        f: impl FnOnce(&mut [&mut dyn ctaphid_dispatch::app::App<'interrupt, N>]) -> T,
    ) -> T;

    #[cfg(feature = "ccid")]
    fn with_ccid_apps<T, const N: usize>(
        &mut self,
        f: impl FnOnce(&mut [&mut dyn apdu_dispatch::app::App<N>]) -> T,
    ) -> T;
}

#[derive(Copy, Clone)]
pub struct Store {
    pub ifs: &'static dyn DynFilesystem,
    pub efs: &'static dyn DynFilesystem,
    pub vfs: &'static dyn DynFilesystem,
}

impl store::Store for Store {
    fn ifs(&self) -> &'static dyn DynFilesystem {
        self.ifs
    }

    fn efs(&self) -> &'static dyn DynFilesystem {
        self.efs
    }

    fn vfs(&self) -> &'static dyn DynFilesystem {
        self.vfs
    }
}

pub struct Platform {
    rng: ChaCha8Rng,
    store: Store,
    ui: UserInterface,
}

impl Platform {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            rng: ChaCha8Rng::from_entropy(),
            ui: UserInterface::new(),
        }
    }
}

impl platform::Platform for Platform {
    type R = ChaCha8Rng;
    type S = Store;
    type UI = UserInterface;

    fn user_interface(&mut self) -> &mut Self::UI {
        &mut self.ui
    }

    fn rng(&mut self) -> &mut Self::R {
        &mut self.rng
    }

    fn store(&self) -> Self::S {
        self.store
    }
}

pub trait Transport<'interrupt, D: Dispatch> {
    fn poll<A: Apps<'interrupt, D>>(&mut self, apps: &mut A) -> io::Result<bool>;

    fn send(&mut self, waiting_for_user: bool) -> io::Result<bool>;

    fn wait(&mut self) -> io::Result<()>;
}

pub struct Runner<D, A> {
    options: Options,
    dispatch: D,
    _marker: PhantomData<A>,
}

impl<D, A> Runner<D, A> {
    pub fn options(&self) -> &Options {
        &self.options
    }
}

impl<'interrupt, D, A> Runner<D, A>
where
    D: Dispatch,
    D::BackendId: Send + Sync,
    D::Context: Send + Sync,
    A: Apps<'interrupt, D>,
{
    pub fn exec<T>(self, platform: Platform, data: A::Data, mut transport: T) -> io::Result<()>
    where
        T: Transport<'interrupt, D>,
    {
        let mut service = Service::with_dispatch(platform, self.dispatch);
        let mut endpoints = Vec::new();
        let (syscall_sender, syscall_receiver) = mpsc::channel();
        let syscall = Syscall(syscall_sender);
        let apps = A::new(&mut service, &mut endpoints, syscall, data);

        thread::scope(move |scope| -> io::Result<()> {
            scope.spawn(move || {
                let mut service = service;
                let mut endpoints = endpoints;
                for _ in syscall_receiver.iter() {
                    service.process(&mut endpoints)
                }
            });

            let mut apps = apps;
            loop {
                let mut did_work = false;
                did_work |= transport.poll(&mut apps)?;
                let waiting = waiting_for_user_presence();
                did_work |= transport.send(waiting)?;
                if !did_work {
                    transport.wait()?;
                }
            }
        })?;

        #[allow(unreachable_code)]
        Ok(())
    }
}

pub struct Builder<D = CoreOnly> {
    options: Options,
    dispatch: D,
}

impl Builder {
    pub fn new(options: Options) -> Self {
        Self {
            options,
            dispatch: Default::default(),
        }
    }
}

impl<D> Builder<D> {
    pub fn dispatch<E>(self, dispatch: E) -> Builder<E> {
        Builder {
            options: self.options,
            dispatch,
        }
    }
}

impl<D: Dispatch> Builder<D> {
    pub fn build<'interrupt, A: Apps<'interrupt, D>>(self) -> Runner<D, A> {
        Runner {
            options: self.options,
            dispatch: self.dispatch,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone)]
pub struct Syscall(Sender<()>);

impl trussed::client::Syscall for Syscall {
    fn syscall(&mut self) {
        log::debug!("syscall");
        self.0.send(()).ok();
    }
}

#[derive(Default)]
pub struct Timeout(Option<std::time::Duration>);

impl Timeout {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update<F: FnOnce() -> Option<std::time::Duration>>(
        &mut self,
        epoch: std::time::Instant,
        keepalive: Option<std::time::Duration>,
        f: F,
    ) -> bool {
        if let Some(timeout) = self.0 {
            if epoch.elapsed() >= timeout {
                self.0 = f().map(|duration| epoch.elapsed() + duration);
                return true;
            }
        } else if let Some(duration) = keepalive {
            self.0 = Some(epoch.elapsed() + duration);
        }
        false
    }
}

fn infer_device_class(ctaphid_enabled: bool, ccid_enabled: bool) -> DeviceClass {
    let interface_count = ctaphid_enabled as u8 + ccid_enabled as u8;

    if ctaphid_enabled && interface_count == 1 {
        DeviceClass::hid()
    } else if interface_count > 1 {
        DeviceClass::composite()
    } else {
        DeviceClass::per_interface()
    }
}
