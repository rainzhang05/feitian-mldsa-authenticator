use ctaphid_dispatch::Dispatch;
use usb_device::bus::{UsbBus, UsbBusAllocator};
use usbd_ctaphid::CtapHid;

pub fn setup<'bus, 'pipe, 'interrupt, B: UsbBus, const N: usize>(
    bus_allocator: &'bus UsbBusAllocator<B>,
    interchange: &'pipe ctaphid_dispatch::Channel<N>,
) -> (
    CtapHid<'bus, 'pipe, 'interrupt, B, N>,
    Dispatch<'pipe, 'interrupt, N>,
) {
    let (ctaphid_rq, ctaphid_rp) = interchange.split().unwrap();
    let ctaphid = CtapHid::new(bus_allocator, ctaphid_rq, 0u32)
        .implements_ctap1()
        .implements_ctap2()
        .implements_wink();
    let ctaphid_dispatch = Dispatch::new(ctaphid_rp);
    (ctaphid, ctaphid_dispatch)
}
