#[cfg(feature = "ccid")]
mod ccid;
#[cfg(feature = "ctaphid")]
mod ctaphid;

use std::{
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender},
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
use usb_device::{
    bus::{UsbBus, UsbBusAllocator},
    device::{UsbDevice, UsbDeviceBuilder, UsbVidPid},
};
use usbip_device::UsbIpBus;

static IS_WAITING: AtomicBool = AtomicBool::new(false);

pub fn set_waiting(waiting: bool) {
    IS_WAITING.store(waiting, Ordering::Relaxed)
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
    fn vid_pid(&self) -> UsbVidPid {
        UsbVidPid(self.vid, self.pid)
    }

    fn resolved_device_class(&self, ctaphid_enabled: bool, ccid_enabled: bool) -> DeviceClass {
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

// virt::Store uses non-static references.  To be able to use the usbip runner with apps that
// require direct access to the store, e. g. provisioner-app, we use a custom store implementation
// with static lifetimes here.
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

    pub fn exec(self, platform: Platform, data: A::Data) {
        // To change IP or port see usbip-device-0.1.4/src/handler.rs:26
        let usbip_bus = UsbIpBus::new();
        usbip_bus.set_device_speed(2);
        let bus_allocator = UsbBusAllocator::new(usbip_bus);

        #[cfg(feature = "ctaphid")]
        let ctap_channel = ctaphid_dispatch::Channel::new();
        #[cfg(feature = "ctaphid")]
        let (mut ctaphid, mut ctaphid_dispatch) = ctaphid::setup::<
            _,
            { ctaphid_dispatch::DEFAULT_MESSAGE_SIZE },
        >(&bus_allocator, &ctap_channel);

        #[cfg(feature = "ccid")]
        let (contact, contactless) = Default::default();
        #[cfg(feature = "ccid")]
        let (mut ccid, mut apdu_dispatch) = ccid::setup(&bus_allocator, &contact, &contactless);

        let mut usb_device = build_device(&bus_allocator, &self.options);
        let mut service = Service::with_dispatch(platform, self.dispatch);
        let mut endpoints = Vec::new();
        let (syscall_sender, syscall_receiver) = mpsc::channel();
        let syscall = Syscall(syscall_sender);
        let mut apps = A::new(&mut service, &mut endpoints, syscall, data);

        log::info!("Ready for work");
        thread::scope(|s| {
            // usb poll + keepalive task
            s.spawn(move || {
                let _epoch = Instant::now();
                #[cfg(feature = "ctaphid")]
                let mut timeout_ctaphid = Timeout::new();
                #[cfg(feature = "ccid")]
                let mut timeout_ccid = Timeout::new();

                loop {
                    let mut handled_usb_event = false;
                    while usb_device.poll(&mut [
                        #[cfg(feature = "ctaphid")]
                        &mut ctaphid,
                        #[cfg(feature = "ccid")]
                        &mut ccid,
                    ]) {
                        handled_usb_event = true;
                    }

                    #[cfg(feature = "ctaphid")]
                    ctaphid::keepalive(&mut ctaphid, &mut timeout_ctaphid, _epoch);
                    #[cfg(feature = "ccid")]
                    ccid::keepalive(&mut ccid, &mut timeout_ccid, _epoch);

                    // USB/IP adds host-side latency. Yield instead of sleeping so control
                    // transfers can complete with minimal turnaround time.
                    if !handled_usb_event {
                        thread::yield_now();
                    }
                }
            });

            // trussed task
            s.spawn(move || {
                for _ in syscall_receiver.iter() {
                    service.process(&mut endpoints)
                }
            });

            // apps task
            loop {
                let mut dispatched = false;

                #[cfg(feature = "ctaphid")]
                {
                    let ctaphid_did_work = apps.with_ctaphid_apps(|apps| {
                        let mut did_work = false;
                        while ctaphid_dispatch.poll(apps) {
                            did_work = true;
                        }
                        did_work
                    });
                    dispatched |= ctaphid_did_work;
                }

                #[cfg(feature = "ccid")]
                {
                    let ccid_did_work = apps.with_ccid_apps(|apps| {
                        let mut did_work = false;
                        while apdu_dispatch.poll(apps).is_some() {
                            did_work = true;
                        }
                        did_work
                    });
                    dispatched |= ccid_did_work;
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

fn build_device<'a, B: UsbBus>(
    bus_allocator: &'a UsbBusAllocator<B>,
    options: &'a Options,
) -> UsbDevice<'a, B> {
    let mut usb_builder = UsbDeviceBuilder::new(bus_allocator, options.vid_pid());
    if let Some(manufacturer) = &options.manufacturer {
        usb_builder = usb_builder.manufacturer(manufacturer);
    }
    if let Some(product) = &options.product {
        usb_builder = usb_builder.product(product);
    }
    if let Some(serial_number) = &options.serial_number {
        usb_builder = usb_builder.serial_number(serial_number);
    }
    let ctaphid_enabled = cfg!(feature = "ctaphid");
    let ccid_enabled = cfg!(feature = "ccid");
    let device_class = options.resolved_device_class(ctaphid_enabled, ccid_enabled);

    log::debug!(
        "USB device descriptor class {:02x}/{:02x}/{:02x} (ctaphid: {}, ccid: {}, override: {})",
        device_class.class,
        device_class.sub_class,
        device_class.protocol,
        ctaphid_enabled,
        ccid_enabled,
        options.device_class.is_some()
    );

    usb_builder
        .device_class(device_class.class)
        .device_sub_class(device_class.sub_class)
        .device_protocol(device_class.protocol)
        .build()
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
