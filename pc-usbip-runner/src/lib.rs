#![allow(clippy::type_complexity)]

#[cfg(feature = "ccid")]
mod ccid;
#[cfg(feature = "ctaphid")]
mod ctaphid;

use std::{any::Any, ptr::NonNull, time::Duration};

#[cfg(feature = "ccid")]
use trussed_host_runner::CcidDispatchRef;
#[cfg(feature = "ctaphid")]
use trussed_host_runner::CtaphidDispatchRef;
use trussed_host_runner::{ctaphid_dispatch, Options, Transport, TransportRuntime};
use usb_device::{
    bus::UsbBusAllocator,
    class::UsbClass,
    device::{UsbDevice, UsbDeviceBuilder, UsbVidPid},
};
use usbip_device::UsbIpBus;

#[cfg(feature = "ccid")]
use {
    apdu_dispatch::{dispatch::ApduDispatch, interchanges::Data},
    interchange,
    usbd_ccid::Ccid,
};
#[cfg(feature = "ctaphid")]
use {ctaphid_dispatch::Channel, usbd_ctaphid::CtapHid};

pub use trussed_host_runner::*;

const USB_SPEED_SUPER: u8 = 2;
#[cfg(feature = "ccid")]
const CCID_BUFFER_SIZE: usize = 3072;

pub struct UsbipTransport;

impl Transport for UsbipTransport {
    fn register(&mut self, options: &Options) -> Box<dyn TransportRuntime> {
        let mut usbip_bus = UsbIpBus::new();
        usbip_bus.set_device_speed(USB_SPEED_SUPER);
        let allocator = Box::new(UsbBusAllocator::new(usbip_bus));
        let allocator_ref: &'static mut UsbBusAllocator<UsbIpBus> = Box::leak(allocator);
        let allocator_ptr = NonNull::from(allocator_ref);

        let usb_device = Box::new(build_device(allocator_ref, options));
        let usb_device_ref: &'static mut UsbDevice<'static, UsbIpBus> = Box::leak(usb_device);
        let usb_device_ptr = NonNull::from(usb_device_ref);

        #[cfg(feature = "ctaphid")]
        let (ctaphid_ptr, ctaphid_dispatch, channel_ptr) = {
            let channel = Box::new(Channel::<{ ctaphid_dispatch::DEFAULT_MESSAGE_SIZE }>::new());
            let channel_ref: &'static Channel<{ ctaphid_dispatch::DEFAULT_MESSAGE_SIZE }> =
                Box::leak(channel);
            let (ctaphid, dispatch) = ctaphid::setup(allocator_ref, channel_ref);
            let ctaphid_ref: &'static mut CtapHid<
                'static,
                'static,
                'static,
                UsbIpBus,
                { ctaphid_dispatch::DEFAULT_MESSAGE_SIZE },
            > = Box::leak(Box::new(ctaphid));
            (
                NonNull::from(ctaphid_ref),
                Some(dispatch),
                NonNull::from(channel_ref),
            )
        };

        #[cfg(feature = "ccid")]
        let (ccid_ptr, apdu_dispatch, contact_ptr, contactless_ptr) = {
            let contact = Box::new(interchange::Channel::<Data, Data>::new());
            let contactless = Box::new(interchange::Channel::<Data, Data>::new());
            let contact_ref: &'static interchange::Channel<Data, Data> = Box::leak(contact);
            let contactless_ref: &'static interchange::Channel<Data, Data> = Box::leak(contactless);
            let (ccid, dispatch) = ccid::setup(allocator_ref, contact_ref, contactless_ref);
            let ccid_ref: &'static mut Ccid<'static, 'static, UsbIpBus, CCID_BUFFER_SIZE> =
                Box::leak(Box::new(ccid));
            (
                NonNull::from(ccid_ref),
                Some(dispatch),
                NonNull::from(contact_ref),
                NonNull::from(contactless_ref),
            )
        };

        Box::new(UsbipRuntime {
            allocator: allocator_ptr,
            usb_device: usb_device_ptr,
            #[cfg(feature = "ctaphid")]
            ctaphid: Some(ctaphid_ptr),
            #[cfg(feature = "ctaphid")]
            ctaphid_dispatch,
            #[cfg(feature = "ctaphid")]
            ctap_channel: Some(channel_ptr),
            #[cfg(feature = "ccid")]
            ccid: Some(ccid_ptr),
            #[cfg(feature = "ccid")]
            apdu_dispatch,
            #[cfg(feature = "ccid")]
            contact: Some(contact_ptr),
            #[cfg(feature = "ccid")]
            contactless: Some(contactless_ptr),
        })
    }

    fn poll(&mut self, runtime: &mut dyn TransportRuntime) -> bool {
        let runtime = runtime
            .as_any_mut()
            .downcast_mut::<UsbipRuntime>()
            .expect("usbip runtime downcast");
        runtime.poll()
    }

    #[cfg(feature = "ctaphid")]
    fn ctaphid_keepalive(
        &mut self,
        runtime: &mut dyn TransportRuntime,
        waiting: bool,
    ) -> (Option<Duration>, Option<Duration>) {
        let runtime = runtime
            .as_any_mut()
            .downcast_mut::<UsbipRuntime>()
            .expect("usbip runtime downcast");
        runtime.ctaphid_keepalive(waiting)
    }

    #[cfg(feature = "ccid")]
    fn ccid_keepalive(
        &mut self,
        runtime: &mut dyn TransportRuntime,
    ) -> (Option<Duration>, Option<Duration>) {
        let runtime = runtime
            .as_any_mut()
            .downcast_mut::<UsbipRuntime>()
            .expect("usbip runtime downcast");
        runtime.ccid_keepalive()
    }
}

struct UsbipRuntime {
    allocator: NonNull<UsbBusAllocator<UsbIpBus>>,
    usb_device: NonNull<UsbDevice<'static, UsbIpBus>>,
    #[cfg(feature = "ctaphid")]
    ctaphid: Option<
        NonNull<
            CtapHid<
                'static,
                'static,
                'static,
                UsbIpBus,
                { ctaphid_dispatch::DEFAULT_MESSAGE_SIZE },
            >,
        >,
    >,
    #[cfg(feature = "ctaphid")]
    ctaphid_dispatch: Option<
        ctaphid_dispatch::Dispatch<'static, 'static, { ctaphid_dispatch::DEFAULT_MESSAGE_SIZE }>,
    >,
    #[cfg(feature = "ctaphid")]
    ctap_channel: Option<NonNull<Channel<{ ctaphid_dispatch::DEFAULT_MESSAGE_SIZE }>>>,
    #[cfg(feature = "ccid")]
    ccid: Option<NonNull<Ccid<'static, 'static, UsbIpBus, CCID_BUFFER_SIZE>>>,
    #[cfg(feature = "ccid")]
    apdu_dispatch: Option<ApduDispatch<'static>>,
    #[cfg(feature = "ccid")]
    contact: Option<NonNull<interchange::Channel<Data, Data>>>,
    #[cfg(feature = "ccid")]
    contactless: Option<NonNull<interchange::Channel<Data, Data>>>,
}

impl UsbipRuntime {
    fn poll(&mut self) -> bool {
        let usb_device = unsafe { self.usb_device.as_mut() };
        let mut handled = false;

        #[cfg(all(feature = "ctaphid", feature = "ccid"))]
        {
            let ctaphid = unsafe { self.ctaphid.expect("ctaphid missing").as_mut() };
            let ccid = unsafe { self.ccid.expect("ccid missing").as_mut() };
            let mut classes: [&mut dyn UsbClass<UsbIpBus>; 2] = [ctaphid, ccid];
            while usb_device.poll(&mut classes) {
                handled = true;
            }
        }

        #[cfg(all(feature = "ctaphid", not(feature = "ccid")))]
        {
            let ctaphid = unsafe { self.ctaphid.expect("ctaphid missing").as_mut() };
            let mut classes: [&mut dyn UsbClass<UsbIpBus>; 1] = [ctaphid];
            while usb_device.poll(&mut classes) {
                handled = true;
            }
        }

        #[cfg(all(feature = "ccid", not(feature = "ctaphid")))]
        {
            let ccid = unsafe { self.ccid.expect("ccid missing").as_mut() };
            let mut classes: [&mut dyn UsbClass<UsbIpBus>; 1] = [ccid];
            while usb_device.poll(&mut classes) {
                handled = true;
            }
        }

        #[cfg(not(any(feature = "ctaphid", feature = "ccid")))]
        while usb_device.poll(&mut []) {
            handled = true;
        }

        handled
    }

    #[cfg(feature = "ctaphid")]
    fn ctaphid_keepalive(&mut self, waiting: bool) -> (Option<Duration>, Option<Duration>) {
        use usbd_ctaphid::types::Status;

        let ctaphid = unsafe { self.ctaphid.expect("ctaphid missing").as_mut() };

        let map_status = |status: Status| match status {
            Status::ReceivedData(ms) => Some(Duration::from_millis(ms.0.into())),
            Status::Idle => None,
        };

        (
            map_status(ctaphid.did_start_processing()),
            map_status(ctaphid.send_keepalive(waiting)),
        )
    }

    #[cfg(feature = "ccid")]
    fn ccid_keepalive(&mut self) -> (Option<Duration>, Option<Duration>) {
        use usbd_ccid::Status;

        let ccid = unsafe { self.ccid.expect("ccid missing").as_mut() };

        let map_status = |status: Status| match status {
            Status::ReceivedData(ms) => Some(Duration::from_millis(ms.0.into())),
            Status::Idle => None,
        };

        (
            map_status(ccid.did_start_processing()),
            map_status(ccid.send_wait_extension()),
        )
    }
}

impl Drop for UsbipRuntime {
    fn drop(&mut self) {
        unsafe {
            #[cfg(feature = "ctaphid")]
            {
                self.ctaphid_dispatch.take();
                if let Some(ctaphid) = self.ctaphid.take() {
                    drop(Box::from_raw(ctaphid.as_ptr()));
                }
                if let Some(channel) = self.ctap_channel.take() {
                    drop(Box::from_raw(channel.as_ptr()));
                }
            }

            #[cfg(feature = "ccid")]
            {
                self.apdu_dispatch.take();
                if let Some(ccid) = self.ccid.take() {
                    drop(Box::from_raw(ccid.as_ptr()));
                }
                if let Some(contact) = self.contact.take() {
                    drop(Box::from_raw(contact.as_ptr()));
                }
                if let Some(contactless) = self.contactless.take() {
                    drop(Box::from_raw(contactless.as_ptr()));
                }
            }

            drop(Box::from_raw(self.usb_device.as_ptr()));
            drop(Box::from_raw(self.allocator.as_ptr()));
        }
    }
}

impl TransportRuntime for UsbipRuntime {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    #[cfg(feature = "ctaphid")]
    fn ctaphid_dispatch<'interrupt>(&mut self) -> Option<CtaphidDispatchRef<'_, 'interrupt>> {
        self.ctaphid_dispatch.as_mut().map(CtaphidDispatchRef::new)
    }

    #[cfg(feature = "ccid")]
    fn ccid_dispatch(&mut self) -> Option<CcidDispatchRef<'_>> {
        self.apdu_dispatch.as_mut().map(CcidDispatchRef::new)
    }
}

fn build_device(
    bus_allocator: &'static UsbBusAllocator<UsbIpBus>,
    options: &Options,
) -> UsbDevice<'static, UsbIpBus> {
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
