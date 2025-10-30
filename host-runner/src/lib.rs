use std::{
    any::Any,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError, Sender},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

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

#[cfg(feature = "ccid")]
pub use apdu_dispatch;
#[cfg(feature = "ctaphid")]
pub use ctaphid_dispatch;

static IS_WAITING: AtomicBool = AtomicBool::new(false);

pub fn set_waiting(waiting: bool) {
    IS_WAITING.store(waiting, Ordering::Relaxed)
}

#[derive(Clone, Debug, Default)]
pub struct ShutdownListener {
    flag: Arc<AtomicBool>,
}

impl ShutdownListener {
    pub fn new(flag: Arc<AtomicBool>) -> Self {
        Self { flag }
    }

    pub fn should_stop(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Debug)]
pub struct ShutdownSignal {
    flag: Arc<AtomicBool>,
}

impl ShutdownSignal {
    pub fn request_shutdown(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }
}

pub fn shutdown_channel() -> (ShutdownSignal, ShutdownListener) {
    let flag = Arc::new(AtomicBool::new(false));
    (
        ShutdownSignal {
            flag: Arc::clone(&flag),
        },
        ShutdownListener { flag },
    )
}

pub type Client<D = CoreOnly> = ClientImplementation<'static, Syscall, D>;

pub type InitPlatform = Box<dyn Fn(&mut Platform)>;

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

pub struct Runner<D, A> {
    options: Options,
    dispatch: D,
    _marker: PhantomData<A>,
}

impl<'interrupt, D: Dispatch, A: Apps<'interrupt, D>> Runner<D, A>
where
    D::BackendId: Send + Sync,
    D::Context: Send + Sync,
{
    pub fn builder(options: Options) -> Builder {
        Builder::new(options)
    }

    pub fn exec(self, platform: Platform, data: A::Data, mut transport: Box<dyn Transport>) {
        self.run_with_shutdown(platform, data, transport, ShutdownListener::default());
    }

    pub fn run_with_shutdown(
        self,
        platform: Platform,
        data: A::Data,
        mut transport: Box<dyn Transport>,
        shutdown: ShutdownListener,
    ) {
        let registration = transport.register(&self.options);
        let runtime = Arc::new(Mutex::new(registration));

        let mut service = Service::with_dispatch(platform, self.dispatch);
        let mut endpoints = Vec::new();
        let (syscall_sender, syscall_receiver) = mpsc::channel();
        let syscall = Syscall(syscall_sender);
        let mut apps = A::new(&mut service, &mut endpoints, syscall, data);

        log::info!("Ready for work");

        thread::scope(|s| {
            let runtime_for_poll = Arc::clone(&runtime);
            let shutdown_poll = shutdown.clone();
            s.spawn(move || {
                let mut transport = transport;
                let _epoch = Instant::now();
                #[cfg(feature = "ctaphid")]
                let mut timeout_ctaphid = Timeout::new();
                #[cfg(feature = "ccid")]
                let mut timeout_ccid = Timeout::new();

                loop {
                    if shutdown_poll.should_stop() {
                        break;
                    }
                    let mut guard = runtime_for_poll
                        .lock()
                        .expect("transport runtime mutex poisoned");
                    let mut handled_usb_event = transport.poll(guard.as_mut());

                    #[cfg(feature = "ctaphid")]
                    {
                        let (started_processing, keepalive) = transport
                            .ctaphid_keepalive(guard.as_mut(), IS_WAITING.load(Ordering::Relaxed));
                        timeout_ctaphid.update(_epoch, started_processing, || keepalive);
                    }

                    #[cfg(feature = "ccid")]
                    {
                        let (started_processing, keepalive) =
                            transport.ccid_keepalive(guard.as_mut());
                        timeout_ccid.update(_epoch, started_processing, || keepalive);
                    }

                    drop(guard);

                    if !handled_usb_event {
                        thread::yield_now();
                    }
                }
            });

            // trussed task
            let shutdown_service = shutdown.clone();
            s.spawn(move || {
                while !shutdown_service.should_stop() {
                    match syscall_receiver.recv_timeout(Duration::from_millis(10)) {
                        Ok(_) => service.process(&mut endpoints),
                        Err(RecvTimeoutError::Timeout) => continue,
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
            });

            // apps task
            let shutdown_main = shutdown;
            loop {
                if shutdown_main.should_stop() {
                    break;
                }
                let mut dispatched = false;

                #[cfg(feature = "ctaphid")]
                {
                    let mut guard = runtime.lock().expect("transport runtime mutex poisoned");
                    if let Some(mut dispatch) = guard.ctaphid_dispatch() {
                        let ctaphid_did_work = apps.with_ctaphid_apps(|apps| {
                            let mut did_work = false;
                            while dispatch.poll(apps) {
                                did_work = true;
                            }
                            did_work
                        });
                        dispatched |= ctaphid_did_work;
                    }
                }

                #[cfg(feature = "ccid")]
                {
                    let mut guard = runtime.lock().expect("transport runtime mutex poisoned");
                    if let Some(mut dispatch) = guard.ccid_dispatch() {
                        let ccid_did_work = apps.with_ccid_apps(|apps| {
                            let mut did_work = false;
                            while dispatch.poll(apps).is_some() {
                                did_work = true;
                            }
                            did_work
                        });
                        dispatched |= ccid_did_work;
                    }
                }

                if !dispatched {
                    thread::yield_now();
                }
            }
        });
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
            _marker: Default::default(),
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

pub trait TransportRuntime: Send {
    fn as_any_mut(&mut self) -> &mut dyn Any;

    #[cfg(feature = "ctaphid")]
    fn ctaphid_dispatch<'interrupt>(&mut self) -> Option<CtaphidDispatchRef<'_, 'interrupt>>;

    #[cfg(feature = "ccid")]
    fn ccid_dispatch(&mut self) -> Option<CcidDispatchRef<'_>>;
}

#[cfg(feature = "ctaphid")]
pub struct CtaphidDispatchRef<'a, 'interrupt> {
    dispatch: &'a mut ctaphid_dispatch::Dispatch<
        'a,
        'interrupt,
        { ctaphid_dispatch::DEFAULT_MESSAGE_SIZE },
    >,
}

#[cfg(feature = "ctaphid")]
impl<'a, 'interrupt> CtaphidDispatchRef<'a, 'interrupt> {
    pub fn new(
        dispatch: &'a mut ctaphid_dispatch::Dispatch<
            'a,
            'interrupt,
            { ctaphid_dispatch::DEFAULT_MESSAGE_SIZE },
        >,
    ) -> Self {
        Self { dispatch }
    }
}

#[cfg(feature = "ctaphid")]
impl<'a, 'interrupt> Deref for CtaphidDispatchRef<'a, 'interrupt> {
    type Target =
        ctaphid_dispatch::Dispatch<'a, 'interrupt, { ctaphid_dispatch::DEFAULT_MESSAGE_SIZE }>;

    fn deref(&self) -> &Self::Target {
        self.dispatch
    }
}

#[cfg(feature = "ctaphid")]
impl<'a, 'interrupt> DerefMut for CtaphidDispatchRef<'a, 'interrupt> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.dispatch
    }
}

#[cfg(feature = "ccid")]
pub struct CcidDispatchRef<'a> {
    dispatch: &'a mut apdu_dispatch::dispatch::ApduDispatch<'a>,
}

#[cfg(feature = "ccid")]
impl<'a> CcidDispatchRef<'a> {
    pub fn new(dispatch: &'a mut apdu_dispatch::dispatch::ApduDispatch<'a>) -> Self {
        Self { dispatch }
    }
}

#[cfg(feature = "ccid")]
impl<'a> Deref for CcidDispatchRef<'a> {
    type Target = apdu_dispatch::dispatch::ApduDispatch<'a>;

    fn deref(&self) -> &Self::Target {
        self.dispatch
    }
}

#[cfg(feature = "ccid")]
impl<'a> DerefMut for CcidDispatchRef<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.dispatch
    }
}

pub trait Transport: Send {
    fn register(&mut self, options: &Options) -> Box<dyn TransportRuntime>;

    fn poll(&mut self, runtime: &mut dyn TransportRuntime) -> bool;

    #[cfg(feature = "ctaphid")]
    fn ctaphid_keepalive(
        &mut self,
        runtime: &mut dyn TransportRuntime,
        waiting: bool,
    ) -> (Option<Duration>, Option<Duration>);

    #[cfg(feature = "ccid")]
    fn ccid_keepalive(
        &mut self,
        runtime: &mut dyn TransportRuntime,
    ) -> (Option<Duration>, Option<Duration>);
}

#[derive(Default)]
pub struct Timeout(Option<Duration>);

impl Timeout {
    fn new() -> Self {
        Self::default()
    }

    fn update<F: FnOnce() -> Option<Duration>>(
        &mut self,
        epoch: Instant,
        keepalive: Option<Duration>,
        f: F,
    ) {
        if let Some(timeout) = self.0 {
            if epoch.elapsed() >= timeout {
                self.0 = f().map(|duration| epoch.elapsed() + duration);
            }
        } else if let Some(duration) = keepalive {
            self.0 = Some(epoch.elapsed() + duration);
        }
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
