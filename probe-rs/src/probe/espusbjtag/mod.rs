//! ESP USB JTAG probe implementation.
mod protocol;

use crate::{
    architecture::{
        arm::{
            communication_interface::{DapProbe, UninitializedArmProbe},
            SwoAccess,
        },
        riscv::{communication_interface::RiscvInterfaceBuilder, dtm::jtag_dtm::JtagDtmBuilder},
        xtensa::communication_interface::{
            XtensaCommunicationInterface, XtensaDebugInterfaceState,
        },
    },
    probe::{
        common::RawJtagIo, DebugProbe, DebugProbeError, DebugProbeSelector, ProbeFactory,
        WireProtocol,
    },
};
use bitvec::prelude::*;

use self::protocol::ProtocolHandler;

use super::{common::JtagDriverState, JTAGAccess};

use probe_rs_target::ScanChainElement;

/// Probe factory for USB JTAG interfaces built into certain ESP32 chips.
#[derive(Debug)]
pub struct EspUsbJtagFactory;

impl std::fmt::Display for EspUsbJtagFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EspJtag")
    }
}

#[async_trait::async_trait(?Send)]
impl ProbeFactory for EspUsbJtagFactory {
    async fn open(
        &self,
        selector: DebugProbeSelector,
    ) -> Result<Box<dyn DebugProbe>, DebugProbeError> {
        let protocol = ProtocolHandler::new_from_selector(&selector).await?;

        Ok(Box::new(EspUsbJtag {
            protocol,
            jtag_state: JtagDriverState::default(),
        }) as Box<dyn DebugProbe>)
    }

    async fn list_probes(&self) -> Vec<super::DebugProbeInfo> {
        protocol::list_espjtag_devices().await
    }
}

/// A USB JTAG interface built into certain ESP32 chips.
#[derive(Debug)]
pub struct EspUsbJtag {
    protocol: ProtocolHandler,

    jtag_state: JtagDriverState,
}

#[async_trait::async_trait(?Send)]
impl RawJtagIo for EspUsbJtag {
    async fn shift_bit(
        &mut self,
        tms: bool,
        tdi: bool,
        capture_tdo: bool,
    ) -> Result<(), DebugProbeError> {
        self.jtag_state.state.update(tms);
        self.protocol.shift_bit(tms, tdi, capture_tdo).await?;
        Ok(())
    }

    async fn read_captured_bits(&mut self) -> Result<BitVec<u8, Lsb0>, DebugProbeError> {
        self.protocol.read_captured_bits().await
    }

    fn state_mut(&mut self) -> &mut JtagDriverState {
        &mut self.jtag_state
    }

    fn state(&self) -> &JtagDriverState {
        &self.jtag_state
    }
}

#[async_trait::async_trait(?Send)]
impl DebugProbe for EspUsbJtag {
    async fn select_protocol(&mut self, protocol: WireProtocol) -> Result<(), DebugProbeError> {
        if matches!(protocol, WireProtocol::Jtag) {
            Ok(())
        } else {
            Err(DebugProbeError::UnsupportedProtocol(protocol))
        }
    }

    fn active_protocol(&self) -> Option<WireProtocol> {
        Some(WireProtocol::Jtag)
    }

    fn get_name(&self) -> &'static str {
        "Esp USB JTAG"
    }

    fn speed_khz(&self) -> u32 {
        self.protocol.base_speed_khz / self.protocol.div_min as u32
    }

    async fn set_speed(&mut self, speed_khz: u32) -> Result<u32, DebugProbeError> {
        // TODO:
        // can only go lower, base speed is max of 40000khz

        Ok(speed_khz)
    }

    async fn set_scan_chain(
        &mut self,
        scan_chain: Vec<ScanChainElement>,
    ) -> Result<(), DebugProbeError> {
        tracing::info!("Setting scan chain to {:?}", scan_chain);
        self.jtag_state.expected_scan_chain = Some(scan_chain);
        Ok(())
    }

    fn scan_chain(&self) -> Result<&[ScanChainElement], DebugProbeError> {
        if let Some(ref scan_chain) = self.jtag_state.expected_scan_chain {
            Ok(scan_chain)
        } else {
            Ok(&[])
        }
    }

    async fn select_jtag_tap(&mut self, index: usize) -> Result<(), DebugProbeError> {
        self.select_target(index)
    }

    async fn attach(&mut self) -> Result<(), DebugProbeError> {
        tracing::debug!("Attaching to ESP USB JTAG");

        self.scan_chain().await?;
        self.select_target(0)
    }

    async fn detach(&mut self) -> Result<(), crate::Error> {
        Ok(())
    }

    async fn target_reset(&mut self) -> Result<(), DebugProbeError> {
        Err(DebugProbeError::NotImplemented {
            function_name: "target_reset",
        })
    }

    async fn target_reset_assert(&mut self) -> Result<(), DebugProbeError> {
        tracing::info!("reset_assert!");
        self.protocol.set_reset(true).await?;
        Ok(())
    }

    async fn target_reset_deassert(&mut self) -> Result<(), DebugProbeError> {
        tracing::info!("reset_deassert!");
        self.protocol.set_reset(false).await?;
        Ok(())
    }

    async fn try_get_riscv_interface_builder<'probe>(
        &'probe mut self,
    ) -> Result<Box<dyn RiscvInterfaceBuilder<'probe> + 'probe>, DebugProbeError> {
        Ok(Box::new(JtagDtmBuilder::new(self)))
    }

    fn get_swo_interface(&self) -> Option<&dyn SwoAccess> {
        // This probe cannot debug ARM targets.
        None
    }

    fn get_swo_interface_mut(&mut self) -> Option<&mut dyn SwoAccess> {
        // This probe cannot debug ARM targets.
        None
    }

    fn has_arm_interface(&self) -> bool {
        // This probe cannot debug ARM targets.
        false
    }

    fn has_riscv_interface(&self) -> bool {
        // This probe is intended for RISC-V.
        true
    }

    fn into_probe(self: Box<Self>) -> Box<dyn DebugProbe> {
        self
    }

    fn try_as_dap_probe(&mut self) -> Option<&mut dyn DapProbe> {
        // This is not a DAP capable probe.
        None
    }

    fn try_get_arm_interface<'probe>(
        self: Box<Self>,
    ) -> Result<Box<dyn UninitializedArmProbe + 'probe>, (Box<dyn DebugProbe>, DebugProbeError)>
    {
        // This probe cannot debug ARM targets.
        Err((
            self,
            DebugProbeError::InterfaceNotAvailable {
                interface_name: "SWD/ARM",
            },
        ))
    }

    async fn get_target_voltage(&mut self) -> Result<Option<f32>, DebugProbeError> {
        // We cannot read the voltage on this probe, unfortunately.
        Ok(None)
    }

    async fn try_get_xtensa_interface<'probe>(
        &'probe mut self,
        state: &'probe mut XtensaDebugInterfaceState,
    ) -> Result<XtensaCommunicationInterface<'probe>, DebugProbeError> {
        Ok(XtensaCommunicationInterface::new(self, state))
    }

    fn has_xtensa_interface(&self) -> bool {
        true
    }
}
