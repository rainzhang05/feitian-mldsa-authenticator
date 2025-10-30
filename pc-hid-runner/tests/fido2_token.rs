#![cfg(target_os = "linux")]

mod common;

use std::{env, process::Command, time::Duration};

use anyhow::{anyhow, Context, Result};
use common::TestRunner;

#[test]
fn fido2_token_lists_and_inspects_device() -> Result<()> {
    if env::var("PC_HID_RUNNER_E2E").is_err() {
        eprintln!("PC_HID_RUNNER_E2E not set; skipping fido2-token smoke test");
        return Ok(());
    }

    let runner = TestRunner::start().context("start HID runner")?;
    let _ = runner
        .wait_for_device(Duration::from_secs(5))
        .context("open hid device")?;

    let nodes = runner
        .wait_for_hidraw_nodes(Duration::from_secs(5))
        .context("locate hidraw nodes")?;
    let hidraw = nodes
        .first()
        .ok_or_else(|| anyhow!("no hidraw nodes for device"))?;

    let list = Command::new("fido2-token")
        .arg("-L")
        .output()
        .context("execute fido2-token -L")?;
    if !list.status.success() {
        return Err(anyhow!(
            "fido2-token -L failed: {}",
            String::from_utf8_lossy(&list.stderr)
        ));
    }
    let listing = String::from_utf8_lossy(&list.stdout);
    if !listing.contains(runner.serial()) {
        return Err(anyhow!(
            "fido2-token -L output did not mention serial {}",
            runner.serial()
        ));
    }

    let info = Command::new("fido2-token")
        .arg("-I")
        .arg(hidraw)
        .output()
        .context("execute fido2-token -I")?;
    if !info.status.success() {
        return Err(anyhow!(
            "fido2-token -I failed: {}",
            String::from_utf8_lossy(&info.stderr)
        ));
    }

    Ok(())
}
