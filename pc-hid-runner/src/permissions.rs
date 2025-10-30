use std::{
    fs::{self, OpenOptions},
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use crate::HidDeviceDescriptor;

pub const UHID_PATH: &str = "/dev/uhid";

pub struct HidrawNode {
    pub path: PathBuf,
    pub mode: u32,
}

pub fn check_uhid_access() -> io::Result<()> {
    let _file = OpenOptions::new().read(true).write(true).open(UHID_PATH)?;
    Ok(())
}

pub fn hidraw_nodes_for_descriptor(
    descriptor: &HidDeviceDescriptor,
) -> io::Result<Vec<HidrawNode>> {
    let mut nodes = Vec::new();
    let sys_hidraw = Path::new("/sys/class/hidraw");
    let entries = match fs::read_dir(sys_hidraw) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(nodes),
        Err(err) => return Err(err),
    };

    for entry in entries.flatten() {
        let sys_path = entry.path();
        let uevent_path = sys_path.join("device").join("uevent");
        let uevent = match fs::read_to_string(&uevent_path) {
            Ok(contents) => contents,
            Err(_) => continue,
        };
        if !matches_descriptor(&uevent, descriptor.vendor_id, descriptor.product_id) {
            continue;
        }
        let dev_name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };
        let dev_path = Path::new("/dev").join(dev_name);
        let metadata = match fs::metadata(&dev_path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let mode = metadata.permissions().mode();
        nodes.push(HidrawNode {
            path: dev_path,
            mode,
        });
    }

    Ok(nodes)
}

fn matches_descriptor(uevent: &str, vendor_id: u32, product_id: u32) -> bool {
    for line in uevent.lines() {
        if let Some(value) = line.strip_prefix("HID_ID=") {
            let mut parts = value.split(':');
            let _bus = parts.next();
            let vendor = parts.next();
            let product = parts.next();
            if let (Some(vendor), Some(product)) = (vendor, product) {
                if let (Ok(vendor), Ok(product)) = (
                    u32::from_str_radix(vendor, 16),
                    u32::from_str_radix(product, 16),
                ) {
                    if vendor == vendor_id && product == product_id {
                        return true;
                    }
                }
            }
        }
    }
    false
}
