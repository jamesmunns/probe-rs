//! This example demonstrates how to do a "recover" operation (erase+unlock a locked chip) on an nRF5340 target.

use anyhow::Result;
use probe_rs::{
    architecture::arm::{DpAddress, FullyQualifiedApAddress},
    probe::list::Lister,
};

#[pollster::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let lister = Lister::new();

    // Get a list of all available debug probes.
    let probes = lister.list_all().await;

    // Use the first probe found.
    let mut probe = probes[0].open().await?;

    probe.attach_to_unspecified().await?;
    let mut iface = probe
        .try_into_arm_interface()
        .unwrap()
        .initialize_unspecified(DpAddress::Default)
        .await
        .unwrap();

    const APP_MEM: FullyQualifiedApAddress = FullyQualifiedApAddress::v1_with_default_dp(0);
    const NET_MEM: FullyQualifiedApAddress = FullyQualifiedApAddress::v1_with_default_dp(1);
    const APP_CTRL: FullyQualifiedApAddress = FullyQualifiedApAddress::v1_with_default_dp(2);
    const NET_CTRL: FullyQualifiedApAddress = FullyQualifiedApAddress::v1_with_default_dp(3);

    const ERASEALL: u8 = 0x04;
    const ERASEALLSTATUS: u8 = 0x08;
    const IDR: u8 = 0xFC;

    for ap in &[APP_MEM, NET_MEM, APP_CTRL, NET_CTRL] {
        println!(
            "IDR {:?} {:x}",
            ap,
            iface.read_raw_ap_register(ap, IDR).await?
        );
    }

    for ap in &[APP_CTRL, NET_CTRL] {
        // Start erase
        iface.write_raw_ap_register(ap, ERASEALL, 1).await?;
        // Wait for erase done
        while iface.read_raw_ap_register(ap, ERASEALLSTATUS).await? != 0 {}
    }

    Ok(())
}
