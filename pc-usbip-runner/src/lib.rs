#![cfg_attr(not(any(feature = "ctaphid", feature = "ccid")), allow(dead_code))]

#[cfg(feature = "ccid")]
mod ccid;
#[cfg(feature = "ctaphid")]
mod ctaphid;

use std::{io, thread, time::Instant};

#[cfg(feature = "ccid")]
use apdu_dispatch::interchanges::Data;
#[cfg(feature = "ctaphid")]
use ctaphid_dispatch::{self, Channel, DEFAULT_MESSAGE_SIZE};
use trussed::backend::Dispatch;
use usb_device::{
    bus::UsbBusAllocator,
    device::{UsbDevice, UsbDeviceBuilder, UsbVidPid},
};
use usbip_device::UsbIpBus;

#[cfg(feature = "ccid")]
use usbd_ccid::Ccid;
#[cfg(feature = "ctaphid")]
use usbd_ctaphid::CtapHid;

pub use transport_core::{
    set_waiting, waiting_for_user_presence, Apps, Builder, Client, DeviceClass, Options, Platform,
    Runner, Store, Syscall, Timeout, Transport,
};

pub struct UsbIpTransport<'bus, 'pipe, 'interrupt> {
    usb_device: &'bus mut UsbDevice<'bus, UsbIpBus>,
    #[cfg(feature = "ctaphid")]
    ctaphid: &'bus mut CtapHid<'bus, 'pipe, 'interrupt, UsbIpBus, { DEFAULT_MESSAGE_SIZE }>,
    #[cfg(feature = "ctaphid")]
    ctaphid_dispatch: ctaphid_dispatch::Dispatch<'pipe, 'interrupt, { DEFAULT_MESSAGE_SIZE }>,
    #[cfg(feature = "ccid")]
    ccid: &'bus mut Ccid<'bus, 'pipe, UsbIpBus, 3072>,
    #[cfg(feature = "ccid")]
    apdu_dispatch: apdu_dispatch::dispatch::ApduDispatch<'pipe>,
    epoch: Instant,
    #[cfg(feature = "ctaphid")]
    timeout_ctaphid: Timeout,
    #[cfg(feature = "ccid")]
    timeout_ccid: Timeout,
}

impl<'bus, 'pipe, 'interrupt> UsbIpTransport<'bus, 'pipe, 'interrupt> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        usb_device: &'bus mut UsbDevice<'bus, UsbIpBus>,
        #[cfg(feature = "ctaphid")] ctaphid: &'bus mut CtapHid<
            'bus,
            'pipe,
            'interrupt,
            UsbIpBus,
            { DEFAULT_MESSAGE_SIZE },
        >,
        #[cfg(feature = "ctaphid")] ctaphid_dispatch: ctaphid_dispatch::Dispatch<
            'pipe,
            'interrupt,
            { DEFAULT_MESSAGE_SIZE },
        >,
        #[cfg(feature = "ccid")] ccid: &'bus mut Ccid<'bus, 'pipe, UsbIpBus, 3072>,
        #[cfg(feature = "ccid")] apdu_dispatch: apdu_dispatch::dispatch::ApduDispatch<'pipe>,
    ) -> Self {
        Self {
            usb_device,
            #[cfg(feature = "ctaphid")]
            ctaphid,
            #[cfg(feature = "ctaphid")]
            ctaphid_dispatch,
            #[cfg(feature = "ccid")]
            ccid,
            #[cfg(feature = "ccid")]
            apdu_dispatch,
            epoch: Instant::now(),
            #[cfg(feature = "ctaphid")]
            timeout_ctaphid: Timeout::new(),
            #[cfg(feature = "ccid")]
            timeout_ccid: Timeout::new(),
        }
    }
}

impl<'interrupt, D> Transport<'interrupt, D> for UsbIpTransport<'_, '_, 'interrupt>
where
    D: Dispatch,
{
    fn poll<A: Apps<'interrupt, D>>(&mut self, apps: &mut A) -> io::Result<bool> {
        let mut handled_usb_event = false;
        while self.usb_device.poll(&mut [
            #[cfg(feature = "ctaphid")]
            &mut *self.ctaphid,
            #[cfg(feature = "ccid")]
            &mut *self.ccid,
        ]) {
            handled_usb_event = true;
        }

        let mut dispatched = false;

        #[cfg(feature = "ctaphid")]
        {
            let ctaphid_did_work = apps.with_ctaphid_apps(|apps| {
                let mut did_work = false;
                while self.ctaphid_dispatch.poll(apps) {
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
                while self.apdu_dispatch.poll(apps).is_some() {
                    did_work = true;
                }
                did_work
            });
            dispatched |= ccid_did_work;
        }

        Ok(handled_usb_event || dispatched)
    }

    fn send(&mut self, waiting_for_user: bool) -> io::Result<bool> {
        let mut keepalive_sent = false;

        #[cfg(feature = "ctaphid")]
        {
            keepalive_sent |= ctaphid::keepalive(
                self.ctaphid,
                &mut self.timeout_ctaphid,
                self.epoch,
                waiting_for_user,
            );
        }

        #[cfg(feature = "ccid")]
        {
            keepalive_sent |= ccid::keepalive(self.ccid, &mut self.timeout_ccid, self.epoch);
        }

        Ok(keepalive_sent)
    }

    fn wait(&mut self) -> io::Result<()> {
        thread::yield_now();
        Ok(())
    }
}

pub fn exec<'interrupt, D, A>(
    runner: Runner<D, A>,
    platform: Platform,
    data: A::Data,
) -> io::Result<()>
where
    D: Dispatch,
    D::BackendId: Send + Sync,
    D::Context: Send + Sync,
    A: Apps<'interrupt, D>,
{
    let usbip_bus = UsbIpBus::new();
    usbip_bus.set_device_speed(2);
    let bus_allocator = UsbBusAllocator::new(usbip_bus);

    #[cfg(feature = "ctaphid")]
    let ctap_channel: Channel<{ DEFAULT_MESSAGE_SIZE }> = Channel::new();
    #[cfg(feature = "ctaphid")]
    let (mut ctaphid, ctaphid_dispatch) =
        ctaphid::setup::<_, { DEFAULT_MESSAGE_SIZE }>(&bus_allocator, &ctap_channel);

    #[cfg(feature = "ccid")]
    let (contact, contactless) = Default::default();
    #[cfg(feature = "ccid")]
    let (mut ccid, apdu_dispatch) = ccid::setup(&bus_allocator, &contact, &contactless);

    let device_options = runner.options().clone();
    let mut usb_device = build_device(&bus_allocator, &device_options);

    let transport = UsbIpTransport::new(
        &mut usb_device,
        #[cfg(feature = "ctaphid")]
        &mut ctaphid,
        #[cfg(feature = "ctaphid")]
        ctaphid_dispatch,
        #[cfg(feature = "ccid")]
        &mut ccid,
        #[cfg(feature = "ccid")]
        apdu_dispatch,
    );

    runner.exec(platform, data, transport)
}

fn build_device<'a>(
    bus_allocator: &'a UsbBusAllocator<UsbIpBus>,
    options: &'a Options,
) -> UsbDevice<'a, UsbIpBus> {
    let mut usb_builder = UsbDeviceBuilder::new(bus_allocator, UsbVidPid(options.vid, options.pid));
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
