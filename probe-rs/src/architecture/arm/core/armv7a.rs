//! Register types and the core interface for armv7-a

use super::{
    instructions::aarch32::{
        build_bx, build_ldc, build_mcr, build_mov, build_mrc, build_mrs, build_stc, build_vmov,
        build_vmrs,
    },
    registers::{
        aarch32::{
            AARCH32_CORE_REGSISTERS, AARCH32_WITH_FP_16_CORE_REGSISTERS,
            AARCH32_WITH_FP_32_CORE_REGSISTERS,
        },
        cortex_m::{FP, PC, RA, SP},
    },
    CortexAState,
};
use crate::{
    architecture::arm::{
        core::armv7a_debug_regs::*, memory::ArmMemoryInterface, sequences::ArmDebugSequence,
        ArmError,
    },
    core::{CoreRegisters, MemoryMappedRegister, RegisterId, RegisterValue},
    error::Error,
    memory::valid_32bit_address,
    Architecture, CoreInformation, CoreInterface, CoreRegister, CoreStatus, CoreType,
    InstructionSet, MemoryInterface,
};
use std::{mem::size_of, sync::Arc, time::Duration};
use web_time::Instant;

/// Errors for the ARMv7-A state machine
#[derive(thiserror::Error, Debug)]
pub enum Armv7aError {
    /// Invalid register number
    #[error("Register number {0} is not valid for ARMv7-A")]
    InvalidRegisterNumber(u16),

    /// Not halted
    #[error("Core is running but operation requires it to be halted")]
    NotHalted,

    /// Data Abort occurred
    #[error("A data abort occurred")]
    DataAbort,
}

/// Interface for interacting with an ARMv7-A core
pub struct Armv7a<'probe> {
    memory: Box<dyn ArmMemoryInterface + 'probe>,

    state: &'probe mut CortexAState,

    base_address: u64,

    sequence: Arc<dyn ArmDebugSequence>,

    num_breakpoints: Option<u32>,

    itr_enabled: bool,
}

impl<'probe> Armv7a<'probe> {
    pub(crate) async fn new(
        mut memory: Box<dyn ArmMemoryInterface + 'probe>,
        state: &'probe mut CortexAState,
        base_address: u64,
        sequence: Arc<dyn ArmDebugSequence>,
    ) -> Result<Self, Error> {
        if !state.initialized() {
            // determine current state
            let address = Dbgdscr::get_mmio_address_from_base(base_address)?;
            let dbgdscr = Dbgdscr(memory.read_word_32(address).await?);

            tracing::debug!("State when connecting: {:x?}", dbgdscr);

            let core_state = if dbgdscr.halted() {
                let reason = dbgdscr.halt_reason();

                tracing::debug!("Core was halted when connecting, reason: {:?}", reason);

                CoreStatus::Halted(reason)
            } else {
                CoreStatus::Running
            };

            state.current_state = core_state;
        }

        let mut core = Self {
            memory,
            state,
            base_address,
            sequence,
            num_breakpoints: None,
            itr_enabled: false,
        };

        if !core.state.initialized() {
            core.reset_register_cache().await;
            core.read_fp_reg_count().await?;
            core.state.initialize();
        }

        Ok(core)
    }

    async fn read_fp_reg_count(&mut self) -> Result<(), Error> {
        if self.state.fp_reg_count == 0 && matches!(self.state.current_state, CoreStatus::Halted(_))
        {
            self.prepare_r0_for_clobber().await?;

            // VMRS r0, MVFR0
            let instruction = build_vmrs(0, 0b0111);
            self.execute_instruction(instruction).await?;

            // Read from r0
            let instruction = build_mcr(14, 0, 0, 0, 5, 0);
            let vmrs = self.execute_instruction_with_result(instruction).await?;

            self.state.fp_reg_count = match vmrs & 0b111 {
                0b001 => 16,
                0b010 => 32,
                _ => 0,
            };
        }

        Ok(())
    }

    /// Execute an instruction
    async fn execute_instruction(&mut self, instruction: u32) -> Result<Dbgdscr, ArmError> {
        if !self.state.current_state.is_halted() {
            return Err(ArmError::CoreNotHalted);
        }

        // Enable ITR if needed
        if !self.itr_enabled {
            let address = Dbgdscr::get_mmio_address_from_base(self.base_address)?;
            let mut dbgdscr = Dbgdscr(self.memory.read_word_32(address).await?);
            dbgdscr.set_itren(true);

            self.memory.write_word_32(address, dbgdscr.into()).await?;

            self.itr_enabled = true;
        }

        // Run instruction
        let address = Dbgitr::get_mmio_address_from_base(self.base_address)?;
        self.memory.write_word_32(address, instruction).await?;

        // Wait for completion
        let address = Dbgdscr::get_mmio_address_from_base(self.base_address)?;
        let mut dbgdscr = Dbgdscr(self.memory.read_word_32(address).await?);

        while !dbgdscr.instrcoml_l() {
            dbgdscr = Dbgdscr(self.memory.read_word_32(address).await?);
        }

        // Check if we had any aborts, if so clear them and fail
        if dbgdscr.adabort_l() || dbgdscr.sdabort_l() {
            let address = Dbgdrcr::get_mmio_address_from_base(self.base_address)?;
            let mut dbgdrcr = Dbgdrcr(0);
            dbgdrcr.set_cse(true);

            self.memory.write_word_32(address, dbgdrcr.into()).await?;

            return Err(Armv7aError::DataAbort.into());
        }

        Ok(dbgdscr)
    }

    /// Execute an instruction on the CPU and return the result
    async fn execute_instruction_with_result(&mut self, instruction: u32) -> Result<u32, Error> {
        // Run instruction
        let mut dbgdscr = self.execute_instruction(instruction).await?;

        // Wait for TXfull
        while !dbgdscr.txfull_l() {
            let address = Dbgdscr::get_mmio_address_from_base(self.base_address)?;
            dbgdscr = Dbgdscr(self.memory.read_word_32(address).await?);
        }

        // Read result
        let address = Dbgdtrtx::get_mmio_address_from_base(self.base_address)?;
        let result = self.memory.read_word_32(address).await?;

        Ok(result)
    }

    async fn execute_instruction_with_input(
        &mut self,
        instruction: u32,
        value: u32,
    ) -> Result<(), Error> {
        // Move value
        let address = Dbgdtrrx::get_mmio_address_from_base(self.base_address)?;
        self.memory.write_word_32(address, value).await?;

        // Wait for RXfull
        let address = Dbgdscr::get_mmio_address_from_base(self.base_address)?;
        let mut dbgdscr = Dbgdscr(self.memory.read_word_32(address).await?);

        while !dbgdscr.rxfull_l() {
            dbgdscr = Dbgdscr(self.memory.read_word_32(address).await?);
        }

        // Run instruction
        self.execute_instruction(instruction).await?;

        Ok(())
    }

    async fn reset_register_cache(&mut self) {
        self.state.register_cache = vec![None; 51];
    }

    /// Sync any updated registers back to the core
    async fn writeback_registers(&mut self) -> Result<(), Error> {
        let writeback_iter = (17u16..=48).chain(15u16..=16).chain(0u16..=14);

        for i in writeback_iter {
            if let Some((val, writeback)) = self.state.register_cache[i as usize] {
                if writeback {
                    match i {
                        0..=14 => {
                            let instruction = build_mrc(14, 0, i, 0, 5, 0);

                            self.execute_instruction_with_input(instruction, val.try_into()?)
                                .await?;
                        }
                        15 => {
                            // Move val to r0
                            let instruction = build_mrc(14, 0, 0, 0, 5, 0);

                            self.execute_instruction_with_input(instruction, val.try_into()?)
                                .await?;

                            // BX r0
                            let instruction = build_bx(0);
                            self.execute_instruction(instruction).await?;
                        }
                        17..=48 => {
                            // Move value to r0, r1
                            let value: u64 = val.try_into()?;
                            let low_word = value as u32;
                            let high_word = (value >> 32) as u32;

                            let instruction = build_mrc(14, 0, 0, 0, 5, 0);
                            self.execute_instruction_with_input(instruction, low_word)
                                .await?;

                            let instruction = build_mrc(14, 0, 1, 0, 5, 0);
                            self.execute_instruction_with_input(instruction, high_word)
                                .await?;

                            // VMOV
                            let instruction = build_vmov(0, 0, 1, i - 17);
                            self.execute_instruction(instruction).await?;
                        }
                        _ => {
                            panic!("Logic missing for writeback of register {i}");
                        }
                    }
                }
            }
        }

        self.reset_register_cache().await;

        Ok(())
    }

    /// Save r0 if needed before it gets clobbered by instruction execution
    async fn prepare_r0_for_clobber(&mut self) -> Result<(), Error> {
        self.prepare_for_clobber(0).await
    }

    /// Save `r<n>` if needed before it gets clobbered by instruction execution
    async fn prepare_for_clobber(&mut self, reg: usize) -> Result<(), Error> {
        if self.state.register_cache[reg].is_none() {
            // cache reg since we're going to clobber it
            let val: u32 = self
                .read_core_reg(RegisterId(reg as u16))
                .await?
                .try_into()?;

            // Mark reg as needing writeback
            self.state.register_cache[reg] = Some((val.into(), true));
        }

        Ok(())
    }

    async fn set_r0(&mut self, value: u32) -> Result<(), Error> {
        let instruction = build_mrc(14, 0, 0, 0, 5, 0);

        self.execute_instruction_with_input(instruction, value)
            .await
    }

    async fn set_core_status(&mut self, new_status: CoreStatus) {
        super::update_core_status(&mut self.memory, &mut self.state.current_state, new_status);
    }
}

#[async_trait::async_trait(?Send)]
impl CoreInterface for Armv7a<'_> {
    async fn wait_for_core_halted(&mut self, timeout: Duration) -> Result<(), Error> {
        // Wait until halted state is active again.
        let start = Instant::now();

        while !self.core_halted().await? {
            if start.elapsed() >= timeout {
                return Err(Error::Arm(ArmError::Timeout));
            }
            // Wait a bit before polling again.
            std::thread::sleep(Duration::from_millis(1));
        }

        Ok(())
    }

    async fn core_halted(&mut self) -> Result<bool, Error> {
        let address = Dbgdscr::get_mmio_address_from_base(self.base_address)?;
        let dbgdscr = Dbgdscr(self.memory.read_word_32(address).await?);

        Ok(dbgdscr.halted())
    }

    async fn status(&mut self) -> Result<crate::core::CoreStatus, Error> {
        // determine current state
        let address = Dbgdscr::get_mmio_address_from_base(self.base_address)?;
        let dbgdscr = Dbgdscr(self.memory.read_word_32(address).await?);

        if dbgdscr.halted() {
            let reason = dbgdscr.halt_reason();

            self.set_core_status(CoreStatus::Halted(reason)).await;

            self.read_fp_reg_count().await?;

            return Ok(CoreStatus::Halted(reason));
        }
        // Core is neither halted nor sleeping, so we assume it is running.
        if self.state.current_state.is_halted() {
            tracing::warn!("Core is running, but we expected it to be halted");
        }

        self.set_core_status(CoreStatus::Running).await;

        Ok(CoreStatus::Running)
    }

    async fn halt(&mut self, timeout: Duration) -> Result<CoreInformation, Error> {
        if !matches!(self.state.current_state, CoreStatus::Halted(_)) {
            let address = Dbgdrcr::get_mmio_address_from_base(self.base_address)?;
            let mut value = Dbgdrcr(0);
            value.set_hrq(true);

            self.memory.write_word_32(address, value.into()).await?;

            self.wait_for_core_halted(timeout).await?;

            // Reset our cached values
            self.reset_register_cache().await;
        }
        // Update core status
        let _ = self.status().await?;

        // try to read the program counter
        let pc_value = self.read_core_reg(self.program_counter().into()).await?;

        // get pc
        Ok(CoreInformation {
            pc: pc_value.try_into()?,
        })
    }
    async fn run(&mut self) -> Result<(), Error> {
        if matches!(self.state.current_state, CoreStatus::Running) {
            return Ok(());
        }

        // set writeback values
        self.writeback_registers().await?;

        let address = Dbgdrcr::get_mmio_address_from_base(self.base_address)?;
        let mut value = Dbgdrcr(0);
        value.set_rrq(true);

        self.memory.write_word_32(address, value.into()).await?;

        // Wait for ack
        let address = Dbgdscr::get_mmio_address_from_base(self.base_address)?;

        loop {
            let dbgdscr = Dbgdscr(self.memory.read_word_32(address).await?);
            if dbgdscr.restarted() {
                break;
            }
        }

        // Recompute / verify current state
        self.set_core_status(CoreStatus::Running).await;
        let _ = self.status().await?;

        Ok(())
    }

    async fn reset(&mut self) -> Result<(), Error> {
        self.sequence
            .reset_system(
                &mut *self.memory,
                crate::CoreType::Armv7a,
                Some(self.base_address),
            )
            .await?;

        // Reset our cached values
        self.reset_register_cache().await;

        Ok(())
    }

    async fn reset_and_halt(&mut self, timeout: Duration) -> Result<CoreInformation, Error> {
        self.sequence
            .reset_catch_set(
                &mut *self.memory,
                crate::CoreType::Armv7a,
                Some(self.base_address),
            )
            .await?;
        self.sequence
            .reset_system(
                &mut *self.memory,
                crate::CoreType::Armv7a,
                Some(self.base_address),
            )
            .await?;

        // Request halt
        let address = Dbgdrcr::get_mmio_address_from_base(self.base_address)?;
        let mut value = Dbgdrcr(0);
        value.set_hrq(true);

        self.memory.write_word_32(address, value.into()).await?;

        // Release from reset
        self.sequence
            .reset_catch_clear(
                &mut *self.memory,
                crate::CoreType::Armv7a,
                Some(self.base_address),
            )
            .await?;

        self.wait_for_core_halted(timeout).await?;

        // Update core status
        let _ = self.status().await?;

        // Reset our cached values
        self.reset_register_cache().await;

        // try to read the program counter
        let pc_value = self.read_core_reg(self.program_counter().into()).await?;

        // get pc
        Ok(CoreInformation {
            pc: pc_value.try_into()?,
        })
    }

    async fn step(&mut self) -> Result<CoreInformation, Error> {
        // Save current breakpoint
        let bp_unit_index = (self.available_breakpoint_units().await? - 1) as usize;
        let bp_value_addr = Dbgbvr::get_mmio_address_from_base(self.base_address)?
            + (bp_unit_index * size_of::<u32>()) as u64;
        let saved_bp_value = self.memory.read_word_32(bp_value_addr).await?;

        let bp_control_addr = Dbgbcr::get_mmio_address_from_base(self.base_address)?
            + (bp_unit_index * size_of::<u32>()) as u64;
        let saved_bp_control = self.memory.read_word_32(bp_control_addr).await?;

        // Set breakpoint for any change
        let current_pc: u32 = self
            .read_core_reg(self.program_counter().into())
            .await?
            .try_into()?;
        let mut bp_control = Dbgbcr(0);

        // Breakpoint type - address mismatch
        bp_control.set_bt(0b0100);
        // Match on all modes
        bp_control.set_hmc(true);
        bp_control.set_pmc(0b11);
        // Match on all bytes
        bp_control.set_bas(0b1111);
        // Enable
        bp_control.set_e(true);

        self.memory.write_word_32(bp_value_addr, current_pc).await?;
        self.memory
            .write_word_32(bp_control_addr, bp_control.into())
            .await?;

        // Resume
        self.run().await?;

        // Wait for halt
        self.wait_for_core_halted(Duration::from_millis(100))
            .await?;

        // Reset breakpoint
        self.memory
            .write_word_32(bp_value_addr, saved_bp_value)
            .await?;
        self.memory
            .write_word_32(bp_control_addr, saved_bp_control)
            .await?;

        // try to read the program counter
        let pc_value = self.read_core_reg(self.program_counter().into()).await?;

        // get pc
        Ok(CoreInformation {
            pc: pc_value.try_into()?,
        })
    }

    async fn read_core_reg(&mut self, address: RegisterId) -> Result<RegisterValue, Error> {
        let reg_num = address.0;

        // check cache
        if (reg_num as usize) < self.state.register_cache.len() {
            if let Some(cached_result) = self.state.register_cache[reg_num as usize] {
                return Ok(cached_result.0);
            }
        }

        // Generate instruction to extract register
        let result: Result<RegisterValue, Error> = match reg_num {
            0..=14 => {
                // r0-r14, valid
                // MCR p14, 0, <Rd>, c0, c5, 0 ; Write DBGDTRTXint Register
                let instruction = build_mcr(14, 0, reg_num, 0, 5, 0);

                let val = self.execute_instruction_with_result(instruction).await?;

                Ok(val.into())
            }
            15 => {
                // PC, must access via r0
                self.prepare_r0_for_clobber().await?;

                // MOV r0, PC
                let instruction = build_mov(0, 15);
                self.execute_instruction(instruction).await?;

                // Read from r0
                let instruction = build_mcr(14, 0, 0, 0, 5, 0);
                let pra_plus_offset = self.execute_instruction_with_result(instruction).await?;

                // PC returned is PC + 8
                Ok((pra_plus_offset - 8).into())
            }
            16 => {
                // CPSR, must access via r0
                self.prepare_r0_for_clobber().await?;

                // MRS r0, CPSR
                let instruction = build_mrs(0);
                self.execute_instruction(instruction).await?;

                // Read from r0
                let instruction = build_mcr(14, 0, 0, 0, 5, 0);
                let cpsr = self.execute_instruction_with_result(instruction).await?;

                Ok(cpsr.into())
            }
            17..=48 => {
                // Access via r0, r1
                self.prepare_for_clobber(0).await?;
                self.prepare_for_clobber(1).await?;

                // If FPEXC.EN = 0, then these registers aren't safe to access.  Read as zero
                let fpexc: u32 = self.read_core_reg(50.into()).await?.try_into()?;
                if (fpexc & (1 << 30)) == 0 {
                    // Disabled
                    return Ok(0u32.into());
                }

                // VMOV r0, r1, <reg>
                let instruction = build_vmov(1, 0, 1, reg_num - 17);
                self.execute_instruction(instruction).await?;

                // Read from r0
                let instruction = build_mcr(14, 0, 0, 0, 5, 0);
                let mut value = self.execute_instruction_with_result(instruction).await? as u64;

                // Read from r1
                let instruction = build_mcr(14, 0, 1, 0, 5, 0);
                value |= (self.execute_instruction_with_result(instruction).await? as u64) << 32;

                Ok(value.into())
            }
            49 => {
                // Access via r0
                self.prepare_for_clobber(0).await?;

                // If FPEXC.EN = 0, then these registers aren't safe to access.  Read as zero
                let fpexc: u32 = self.read_core_reg(50.into()).await?.try_into()?;
                if (fpexc & (1 << 30)) == 0 {
                    // Disabled
                    return Ok(0u32.into());
                }

                // VMRS r0, FPSCR
                let instruction = build_vmrs(0, 1);
                self.execute_instruction(instruction).await?;

                // Read from r0
                let instruction = build_mcr(14, 0, 0, 0, 5, 0);
                let value = self.execute_instruction_with_result(instruction).await?;

                Ok(value.into())
            }
            50 => {
                // Access via r0
                self.prepare_for_clobber(0).await?;

                // VMRS r0, FPEXC
                let instruction = build_vmrs(0, 0b1000);
                self.execute_instruction(instruction).await?;

                let instruction = build_mcr(14, 0, 0, 0, 5, 0);
                let value = self.execute_instruction_with_result(instruction).await?;

                Ok(value.into())
            }
            _ => Err(Error::Arm(
                Armv7aError::InvalidRegisterNumber(reg_num).into(),
            )),
        };

        if let Ok(value) = result {
            self.state.register_cache[reg_num as usize] = Some((value, false));

            Ok(value)
        } else {
            Err(result.err().unwrap())
        }
    }

    async fn write_core_reg(
        &mut self,
        address: RegisterId,
        value: RegisterValue,
    ) -> Result<(), Error> {
        let reg_num = address.0;

        if (reg_num as usize) >= self.state.register_cache.len() {
            return Err(Error::Arm(
                Armv7aError::InvalidRegisterNumber(reg_num).into(),
            ));
        }
        self.state.register_cache[reg_num as usize] = Some((value, true));

        Ok(())
    }

    async fn available_breakpoint_units(&mut self) -> Result<u32, Error> {
        if self.num_breakpoints.is_none() {
            let address = Dbgdidr::get_mmio_address_from_base(self.base_address)?;
            let dbgdidr = Dbgdidr(self.memory.read_word_32(address).await?);

            self.num_breakpoints = Some(dbgdidr.brps() + 1);
        }
        Ok(self.num_breakpoints.unwrap())
    }

    /// See docs on the [`CoreInterface::hw_breakpoints`] trait
    async fn hw_breakpoints(&mut self) -> Result<Vec<Option<u64>>, Error> {
        let mut breakpoints = vec![];
        let num_hw_breakpoints = self.available_breakpoint_units().await? as usize;

        for bp_unit_index in 0..num_hw_breakpoints {
            let bp_value_addr = Dbgbvr::get_mmio_address_from_base(self.base_address)?
                + (bp_unit_index * size_of::<u32>()) as u64;
            let bp_value = self.memory.read_word_32(bp_value_addr).await?;

            let bp_control_addr = Dbgbcr::get_mmio_address_from_base(self.base_address)?
                + (bp_unit_index * size_of::<u32>()) as u64;
            let bp_control = Dbgbcr(self.memory.read_word_32(bp_control_addr).await?);

            if bp_control.e() {
                breakpoints.push(Some(bp_value as u64));
            } else {
                breakpoints.push(None);
            }
        }
        Ok(breakpoints)
    }

    async fn enable_breakpoints(&mut self, _state: bool) -> Result<(), Error> {
        // Breakpoints are always on with v7-A
        Ok(())
    }

    async fn set_hw_breakpoint(&mut self, bp_unit_index: usize, addr: u64) -> Result<(), Error> {
        let addr = valid_32bit_address(addr)?;

        let bp_value_addr = Dbgbvr::get_mmio_address_from_base(self.base_address)?
            + (bp_unit_index * size_of::<u32>()) as u64;
        let bp_control_addr = Dbgbcr::get_mmio_address_from_base(self.base_address)?
            + (bp_unit_index * size_of::<u32>()) as u64;
        let mut bp_control = Dbgbcr(0);

        // Breakpoint type - address match
        bp_control.set_bt(0b0000);
        // Match on all modes
        bp_control.set_hmc(true);
        bp_control.set_pmc(0b11);
        // Match on all bytes
        bp_control.set_bas(0b1111);
        // Enable
        bp_control.set_e(true);

        self.memory.write_word_32(bp_value_addr, addr).await?;
        self.memory
            .write_word_32(bp_control_addr, bp_control.into())
            .await?;

        Ok(())
    }

    async fn clear_hw_breakpoint(&mut self, bp_unit_index: usize) -> Result<(), Error> {
        let bp_value_addr = Dbgbvr::get_mmio_address_from_base(self.base_address)?
            + (bp_unit_index * size_of::<u32>()) as u64;
        let bp_control_addr = Dbgbcr::get_mmio_address_from_base(self.base_address)?
            + (bp_unit_index * size_of::<u32>()) as u64;

        self.memory.write_word_32(bp_value_addr, 0).await?;
        self.memory.write_word_32(bp_control_addr, 0).await?;

        Ok(())
    }

    fn registers(&self) -> &'static CoreRegisters {
        match self.state.fp_reg_count {
            16 => &AARCH32_WITH_FP_16_CORE_REGSISTERS,
            32 => &AARCH32_WITH_FP_32_CORE_REGSISTERS,
            _ => &AARCH32_CORE_REGSISTERS,
        }
    }

    fn program_counter(&self) -> &'static CoreRegister {
        &PC
    }

    fn frame_pointer(&self) -> &'static CoreRegister {
        &FP
    }

    fn stack_pointer(&self) -> &'static CoreRegister {
        &SP
    }

    fn return_address(&self) -> &'static CoreRegister {
        &RA
    }

    fn hw_breakpoints_enabled(&self) -> bool {
        true
    }

    fn architecture(&self) -> Architecture {
        Architecture::Arm
    }

    fn core_type(&self) -> CoreType {
        CoreType::Armv7a
    }

    async fn instruction_set(&mut self) -> Result<InstructionSet, Error> {
        let cpsr: u32 = self.read_core_reg(RegisterId(16)).await?.try_into()?;

        // CPSR bit 5 - T - Thumb mode
        match (cpsr >> 5) & 1 {
            1 => Ok(InstructionSet::Thumb2),
            _ => Ok(InstructionSet::A32),
        }
    }

    async fn fpu_support(&mut self) -> Result<bool, Error> {
        Ok(self.state.fp_reg_count != 0)
    }

    fn floating_point_register_count(&mut self) -> Result<usize, Error> {
        Ok(self.state.fp_reg_count)
    }

    #[tracing::instrument(skip(self))]
    async fn reset_catch_set(&mut self) -> Result<(), Error> {
        self.sequence
            .reset_catch_set(&mut *self.memory, CoreType::Armv7a, Some(self.base_address))
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn reset_catch_clear(&mut self) -> Result<(), Error> {
        // Clear the reset_catch bit which was set earlier.
        self.sequence
            .reset_catch_clear(&mut *self.memory, CoreType::Armv7a, Some(self.base_address))
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn debug_core_stop(&mut self) -> Result<(), Error> {
        if matches!(self.state.current_state, CoreStatus::Halted(_)) {
            // We may have clobbered registers we wrote during debugging
            // Best effort attempt to put them back before we exit debug mode
            self.writeback_registers().await?;
        }

        self.sequence
            .debug_core_stop(&mut *self.memory, CoreType::Armv7a)
            .await?;

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl MemoryInterface for Armv7a<'_> {
    async fn supports_native_64bit_access(&mut self) -> bool {
        false
    }

    async fn read_word_64(&mut self, address: u64) -> Result<u64, Error> {
        let mut ret: u64 = self.read_word_32(address).await? as u64;
        ret |= (self.read_word_32(address + 4).await? as u64) << 32;

        Ok(ret)
    }

    async fn read_word_32(&mut self, address: u64) -> Result<u32, Error> {
        let address = valid_32bit_address(address)?;

        // LDC p14, c5, [r0], #4
        let instr = build_ldc(14, 5, 0, 4);

        // Save r0
        self.prepare_r0_for_clobber().await?;

        // Load r0 with the address to read from
        self.set_r0(address).await?;

        // Read memory from [r0]
        self.execute_instruction_with_result(instr).await
    }

    async fn read_word_16(&mut self, address: u64) -> Result<u16, Error> {
        // Find the word this is in and its byte offset
        let byte_offset = address % 4;
        let word_start = address - byte_offset;

        // Read the word
        let data = self.read_word_32(word_start).await?;

        // Return the byte
        Ok((data >> (byte_offset * 8)) as u16)
    }

    async fn read_word_8(&mut self, address: u64) -> Result<u8, Error> {
        // Find the word this is in and its byte offset
        let byte_offset = address % 4;
        let word_start = address - byte_offset;

        // Read the word
        let data = self.read_word_32(word_start).await?;

        // Return the byte
        Ok(data.to_le_bytes()[byte_offset as usize])
    }

    async fn read_64(&mut self, address: u64, data: &mut [u64]) -> Result<(), Error> {
        for (i, word) in data.iter_mut().enumerate() {
            *word = self.read_word_64(address + ((i as u64) * 8)).await?;
        }

        Ok(())
    }

    async fn read_32(&mut self, address: u64, data: &mut [u32]) -> Result<(), Error> {
        for (i, word) in data.iter_mut().enumerate() {
            *word = self.read_word_32(address + ((i as u64) * 4)).await?;
        }

        Ok(())
    }

    async fn read_16(&mut self, address: u64, data: &mut [u16]) -> Result<(), Error> {
        for (i, word) in data.iter_mut().enumerate() {
            *word = self.read_word_16(address + ((i as u64) * 2)).await?;
        }

        Ok(())
    }

    async fn read_8(&mut self, address: u64, data: &mut [u8]) -> Result<(), Error> {
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = self.read_word_8(address + (i as u64)).await?;
        }

        Ok(())
    }

    async fn write_word_64(&mut self, address: u64, data: u64) -> Result<(), Error> {
        let data_low = data as u32;
        let data_high = (data >> 32) as u32;

        self.write_word_32(address, data_low).await?;
        self.write_word_32(address + 4, data_high).await
    }

    async fn write_word_32(&mut self, address: u64, data: u32) -> Result<(), Error> {
        let address = valid_32bit_address(address)?;

        // STC p14, c5, [r0], #4
        let instr = build_stc(14, 5, 0, 4);

        // Save r0
        self.prepare_r0_for_clobber().await?;

        // Load r0 with the address to write to
        self.set_r0(address).await?;

        // Write to [r0]
        self.execute_instruction_with_input(instr, data).await
    }

    async fn write_word_8(&mut self, address: u64, data: u8) -> Result<(), Error> {
        // Find the word this is in and its byte offset
        let byte_offset = address % 4;
        let word_start = address - byte_offset;

        // Get the current word value
        let current_word = self.read_word_32(word_start).await?;
        let mut word_bytes = current_word.to_le_bytes();
        word_bytes[byte_offset as usize] = data;

        self.write_word_32(word_start, u32::from_le_bytes(word_bytes))
            .await
    }

    async fn write_word_16(&mut self, address: u64, data: u16) -> Result<(), Error> {
        // Find the word this is in and its byte offset
        let byte_offset = address % 4;
        let word_start = address - byte_offset;

        // Get the current word value
        let mut word = self.read_word_32(word_start).await?;

        // patch the word into it
        word &= !(0xFFFFu32 << (byte_offset * 8));
        word |= (data as u32) << (byte_offset * 8);

        self.write_word_32(word_start, word).await
    }

    async fn write_64(&mut self, address: u64, data: &[u64]) -> Result<(), Error> {
        for (i, word) in data.iter().enumerate() {
            self.write_word_64(address + ((i as u64) * 8), *word)
                .await?;
        }

        Ok(())
    }

    async fn write_32(&mut self, address: u64, data: &[u32]) -> Result<(), Error> {
        for (i, word) in data.iter().enumerate() {
            self.write_word_32(address + ((i as u64) * 4), *word)
                .await?;
        }

        Ok(())
    }

    async fn write_16(&mut self, address: u64, data: &[u16]) -> Result<(), Error> {
        for (i, word) in data.iter().enumerate() {
            self.write_word_16(address + ((i as u64) * 2), *word)
                .await?;
        }

        Ok(())
    }

    async fn write_8(&mut self, address: u64, data: &[u8]) -> Result<(), Error> {
        for (i, byte) in data.iter().enumerate() {
            self.write_word_8(address + (i as u64), *byte).await?;
        }

        Ok(())
    }

    async fn supports_8bit_transfers(&self) -> Result<bool, Error> {
        Ok(false)
    }

    async fn flush(&mut self) -> Result<(), Error> {
        // Nothing to do - this runs through the CPU which automatically handles any caching
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        architecture::arm::{
            ap::memory_ap::MemoryAp, communication_interface::SwdSequence,
            sequences::DefaultArmSequence,
        },
        probe::DebugProbeError,
    };

    use super::*;

    const TEST_BASE_ADDRESS: u64 = 0x8000_1000;

    fn address_to_reg_num(address: u64) -> u32 {
        ((address - TEST_BASE_ADDRESS) / 4) as u32
    }

    pub struct ExpectedMemoryOp {
        read: bool,
        address: u64,
        value: u32,
    }

    pub struct MockProbe {
        expected_ops: Vec<ExpectedMemoryOp>,
    }

    impl MockProbe {
        pub fn new() -> Self {
            MockProbe {
                expected_ops: vec![],
            }
        }

        pub fn expected_read(&mut self, addr: u64, value: u32) {
            self.expected_ops.push(ExpectedMemoryOp {
                read: true,
                address: addr,
                value,
            });
        }

        pub fn expected_write(&mut self, addr: u64, value: u32) {
            self.expected_ops.push(ExpectedMemoryOp {
                read: false,
                address: addr,
                value,
            });
        }
    }

    #[async_trait::async_trait(?Send)]
    impl MemoryInterface<ArmError> for MockProbe {
        async fn read_8(&mut self, _address: u64, _data: &mut [u8]) -> Result<(), ArmError> {
            todo!()
        }

        async fn read_16(&mut self, _address: u64, _data: &mut [u16]) -> Result<(), ArmError> {
            todo!()
        }

        async fn read_32(&mut self, address: u64, data: &mut [u32]) -> Result<(), ArmError> {
            if self.expected_ops.is_empty() {
                panic!(
                    "Received unexpected read_32 op: register {:#}",
                    address_to_reg_num(address)
                );
            }

            assert_eq!(data.len(), 1);

            let expected_op = self.expected_ops.remove(0);

            assert!(
                expected_op.read,
                "R/W mismatch for register: Expected {:#} Actual: {:#}",
                address_to_reg_num(expected_op.address),
                address_to_reg_num(address)
            );
            assert_eq!(
                expected_op.address,
                address,
                "Read from unexpected register: Expected {:#} Actual: {:#}",
                address_to_reg_num(expected_op.address),
                address_to_reg_num(address)
            );

            data[0] = expected_op.value;

            Ok(())
        }

        async fn read(&mut self, address: u64, data: &mut [u8]) -> Result<(), ArmError> {
            self.read_8(address, data).await
        }

        async fn write_8(&mut self, _address: u64, _data: &[u8]) -> Result<(), ArmError> {
            todo!()
        }

        async fn write_16(&mut self, _address: u64, _data: &[u16]) -> Result<(), ArmError> {
            todo!()
        }

        async fn write_32(&mut self, address: u64, data: &[u32]) -> Result<(), ArmError> {
            if self.expected_ops.is_empty() {
                panic!(
                    "Received unexpected write_32 op: register {:#}",
                    address_to_reg_num(address)
                );
            }

            assert_eq!(data.len(), 1);

            let expected_op = self.expected_ops.remove(0);

            assert!(
                !expected_op.read,
                "Read/write mismatch on register: {:#}",
                address_to_reg_num(address)
            );
            assert_eq!(
                expected_op.address,
                address,
                "Write to unexpected register: Expected {:#} Actual: {:#}",
                address_to_reg_num(expected_op.address),
                address_to_reg_num(address)
            );

            assert_eq!(
                expected_op.value, data[0],
                "Write value mismatch Expected {:#X} Actual: {:#X}",
                expected_op.value, data[0]
            );

            Ok(())
        }

        async fn write(&mut self, address: u64, data: &[u8]) -> Result<(), ArmError> {
            self.write_8(address, data).await
        }

        async fn flush(&mut self) -> Result<(), ArmError> {
            todo!()
        }

        async fn read_64(&mut self, _address: u64, _data: &mut [u64]) -> Result<(), ArmError> {
            todo!()
        }

        async fn write_64(&mut self, _address: u64, _data: &[u64]) -> Result<(), ArmError> {
            todo!()
        }

        async fn supports_8bit_transfers(&self) -> Result<bool, ArmError> {
            Ok(false)
        }

        async fn supports_native_64bit_access(&mut self) -> bool {
            false
        }
    }

    #[async_trait::async_trait(?Send)]
    impl ArmMemoryInterface for MockProbe {
        fn update_core_status(&mut self, _: CoreStatus) {}

        fn get_arm_communication_interface(
            &mut self,
        ) -> Result<
            &mut crate::architecture::arm::ArmCommunicationInterface<
                crate::architecture::arm::communication_interface::Initialized,
            >,
            DebugProbeError,
        > {
            Err(DebugProbeError::NotImplemented {
                function_name: "get_arm_communication_interface",
            })
        }

        fn try_as_parts(
            &mut self,
        ) -> Result<
            (
                &mut crate::architecture::arm::ArmCommunicationInterface<
                    crate::architecture::arm::communication_interface::Initialized,
                >,
                &mut MemoryAp,
            ),
            DebugProbeError,
        > {
            todo!()
        }

        fn ap(&mut self) -> &mut MemoryAp {
            todo!()
        }

        async fn base_address(&mut self) -> Result<u64, ArmError> {
            todo!()
        }
    }

    #[async_trait::async_trait(?Send)]
    impl SwdSequence for MockProbe {
        async fn swj_sequence(&mut self, _bit_len: u8, _bits: u64) -> Result<(), DebugProbeError> {
            todo!()
        }

        async fn swj_pins(
            &mut self,
            _pin_out: u32,
            _pin_select: u32,
            _pin_wait: u32,
        ) -> Result<u32, DebugProbeError> {
            todo!()
        }
    }

    fn add_status_expectations(probe: &mut MockProbe, halted: bool) {
        let mut dbgdscr = Dbgdscr(0);
        dbgdscr.set_halted(halted);
        dbgdscr.set_restarted(true);
        probe.expected_read(
            Dbgdscr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdscr.into(),
        );
    }

    fn add_enable_itr_expectations(probe: &mut MockProbe) {
        let mut dbgdscr = Dbgdscr(0);
        dbgdscr.set_halted(true);
        probe.expected_read(
            Dbgdscr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdscr.into(),
        );
        dbgdscr.set_itren(true);
        probe.expected_write(
            Dbgdscr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdscr.into(),
        );
    }

    fn add_read_reg_expectations(probe: &mut MockProbe, reg: u16, value: u32) {
        probe.expected_write(
            Dbgitr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            build_mcr(14, 0, reg, 0, 5, 0),
        );
        let mut dbgdscr = Dbgdscr(0);
        dbgdscr.set_instrcoml_l(true);
        dbgdscr.set_txfull_l(true);

        probe.expected_read(
            Dbgdscr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdscr.into(),
        );
        probe.expected_read(
            Dbgdtrtx::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            value,
        );
    }

    fn add_read_pc_expectations(probe: &mut MockProbe, value: u32) {
        let mut dbgdscr = Dbgdscr(0);
        dbgdscr.set_instrcoml_l(true);
        dbgdscr.set_txfull_l(true);

        probe.expected_write(
            Dbgitr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            build_mov(0, 15),
        );
        probe.expected_read(
            Dbgdscr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdscr.into(),
        );
        // + 8 to add expected offset on halt
        add_read_reg_expectations(probe, 0, value + 8);
    }

    fn add_read_fp_count_expectations(probe: &mut MockProbe) {
        let mut dbgdscr = Dbgdscr(0);
        dbgdscr.set_instrcoml_l(true);
        dbgdscr.set_txfull_l(true);

        probe.expected_write(
            Dbgitr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            build_vmrs(0, 0b0111),
        );
        probe.expected_read(
            Dbgdscr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdscr.into(),
        );
        add_read_reg_expectations(probe, 0, 0b010);
    }

    fn add_read_cpsr_expectations(probe: &mut MockProbe, value: u32) {
        let mut dbgdscr = Dbgdscr(0);
        dbgdscr.set_instrcoml_l(true);
        dbgdscr.set_txfull_l(true);

        probe.expected_write(
            Dbgitr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            build_mrs(0),
        );
        probe.expected_read(
            Dbgdscr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdscr.into(),
        );
        add_read_reg_expectations(probe, 0, value);
    }

    fn add_idr_expectations(probe: &mut MockProbe, bp_count: u32) {
        let mut dbgdidr = Dbgdidr(0);
        dbgdidr.set_brps(bp_count - 1);
        probe.expected_read(
            Dbgdidr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdidr.into(),
        );
    }

    fn add_set_r0_expectation(probe: &mut MockProbe, value: u32) {
        let mut dbgdscr = Dbgdscr(0);
        dbgdscr.set_instrcoml_l(true);
        dbgdscr.set_rxfull_l(true);

        probe.expected_write(
            Dbgdtrrx::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            value,
        );
        probe.expected_read(
            Dbgdscr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdscr.into(),
        );

        probe.expected_write(
            Dbgitr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            build_mrc(14, 0, 0, 0, 5, 0),
        );
        probe.expected_read(
            Dbgdscr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdscr.into(),
        );
    }

    fn add_read_memory_expectations(probe: &mut MockProbe, address: u64, value: u32) {
        add_set_r0_expectation(probe, address as u32);

        let mut dbgdscr = Dbgdscr(0);
        dbgdscr.set_instrcoml_l(true);
        dbgdscr.set_txfull_l(true);

        probe.expected_write(
            Dbgitr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            build_ldc(14, 5, 0, 4),
        );
        probe.expected_read(
            Dbgdscr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdscr.into(),
        );
        probe.expected_read(
            Dbgdtrtx::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            value,
        );
    }

    #[pollster::test]
    async fn armv7a_new() {
        let mut probe = MockProbe::new();

        // Add expectations
        add_status_expectations(&mut probe, true);
        add_enable_itr_expectations(&mut probe);
        add_read_reg_expectations(&mut probe, 0, 0);
        add_read_fp_count_expectations(&mut probe);

        let mock_mem = Box::new(probe) as _;

        let _ = Armv7a::new(
            mock_mem,
            &mut CortexAState::new(),
            TEST_BASE_ADDRESS,
            DefaultArmSequence::create(),
        )
        .await
        .unwrap();
    }

    #[pollster::test]
    async fn armv7a_core_halted() {
        let mut probe = MockProbe::new();
        let mut state = CortexAState::new();

        // Add expectations
        add_status_expectations(&mut probe, true);
        add_enable_itr_expectations(&mut probe);
        add_read_reg_expectations(&mut probe, 0, 0);
        add_read_fp_count_expectations(&mut probe);

        let mut dbgdscr = Dbgdscr(0);
        dbgdscr.set_halted(false);
        probe.expected_read(
            Dbgdscr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdscr.into(),
        );

        dbgdscr.set_halted(true);
        probe.expected_read(
            Dbgdscr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdscr.into(),
        );

        let mock_mem = Box::new(probe) as _;

        let mut armv7a = Armv7a::new(
            mock_mem,
            &mut state,
            TEST_BASE_ADDRESS,
            DefaultArmSequence::create(),
        )
        .await
        .unwrap();

        // First read false, second read true
        assert!(!armv7a.core_halted().await.unwrap());
        assert!(armv7a.core_halted().await.unwrap());
    }

    #[pollster::test]
    async fn armv7a_wait_for_core_halted() {
        let mut probe = MockProbe::new();
        let mut state = CortexAState::new();

        // Add expectations
        add_status_expectations(&mut probe, true);
        add_enable_itr_expectations(&mut probe);
        add_read_reg_expectations(&mut probe, 0, 0);
        add_read_fp_count_expectations(&mut probe);

        let mut dbgdscr = Dbgdscr(0);
        dbgdscr.set_halted(false);
        probe.expected_read(
            Dbgdscr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdscr.into(),
        );

        dbgdscr.set_halted(true);
        probe.expected_read(
            Dbgdscr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdscr.into(),
        );

        let mock_mem = Box::new(probe) as _;

        let mut armv7a = Armv7a::new(
            mock_mem,
            &mut state,
            TEST_BASE_ADDRESS,
            DefaultArmSequence::create(),
        )
        .await
        .unwrap();

        // Should halt on second read
        armv7a
            .wait_for_core_halted(Duration::from_millis(100))
            .await
            .unwrap();
    }

    #[pollster::test]
    async fn armv7a_status_running() {
        let mut probe = MockProbe::new();
        let mut state = CortexAState::new();

        // Add expectations
        add_status_expectations(&mut probe, true);
        add_enable_itr_expectations(&mut probe);
        add_read_reg_expectations(&mut probe, 0, 0);
        add_read_fp_count_expectations(&mut probe);

        let mut dbgdscr = Dbgdscr(0);
        dbgdscr.set_halted(false);
        probe.expected_read(
            Dbgdscr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdscr.into(),
        );

        let mock_mem = Box::new(probe) as _;

        let mut armv7a = Armv7a::new(
            mock_mem,
            &mut state,
            TEST_BASE_ADDRESS,
            DefaultArmSequence::create(),
        )
        .await
        .unwrap();

        // Should halt on second read
        assert_eq!(CoreStatus::Running, armv7a.status().await.unwrap());
    }

    #[pollster::test]
    async fn armv7a_status_halted() {
        let mut probe = MockProbe::new();
        let mut state = CortexAState::new();

        // Add expectations
        add_status_expectations(&mut probe, true);
        add_enable_itr_expectations(&mut probe);
        add_read_reg_expectations(&mut probe, 0, 0);
        add_read_fp_count_expectations(&mut probe);

        let mut dbgdscr = Dbgdscr(0);
        dbgdscr.set_halted(true);
        probe.expected_read(
            Dbgdscr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdscr.into(),
        );
        add_read_fp_count_expectations(&mut probe);

        let mock_mem = Box::new(probe) as _;

        let mut armv7a = Armv7a::new(
            mock_mem,
            &mut state,
            TEST_BASE_ADDRESS,
            DefaultArmSequence::create(),
        )
        .await
        .unwrap();

        // Should halt on second read
        assert_eq!(
            CoreStatus::Halted(crate::HaltReason::Request),
            armv7a.status().await.unwrap()
        );
    }

    #[pollster::test]
    async fn armv7a_read_core_reg_common() {
        const REG_VALUE: u32 = 0xABCD;

        let mut probe = MockProbe::new();
        let mut state = CortexAState::new();

        // Add expectations
        add_status_expectations(&mut probe, true);
        add_enable_itr_expectations(&mut probe);
        add_read_reg_expectations(&mut probe, 0, 0);
        add_read_fp_count_expectations(&mut probe);

        // Read register
        add_read_reg_expectations(&mut probe, 2, REG_VALUE);

        let mock_mem = Box::new(probe) as _;

        let mut armv7a = Armv7a::new(
            mock_mem,
            &mut state,
            TEST_BASE_ADDRESS,
            DefaultArmSequence::create(),
        )
        .await
        .unwrap();

        // First read will hit expectations
        assert_eq!(
            RegisterValue::from(REG_VALUE),
            armv7a.read_core_reg(RegisterId(2)).await.unwrap()
        );

        // Second read will cache, no new expectations
        assert_eq!(
            RegisterValue::from(REG_VALUE),
            armv7a.read_core_reg(RegisterId(2)).await.unwrap()
        );
    }

    #[pollster::test]
    async fn armv7a_read_core_reg_pc() {
        const REG_VALUE: u32 = 0xABCD;

        let mut probe = MockProbe::new();
        let mut state = CortexAState::new();

        // Add expectations
        add_status_expectations(&mut probe, true);
        add_enable_itr_expectations(&mut probe);
        add_read_reg_expectations(&mut probe, 0, 0);
        add_read_fp_count_expectations(&mut probe);

        // Read PC
        add_read_pc_expectations(&mut probe, REG_VALUE);

        let mock_mem = Box::new(probe) as _;

        let mut armv7a = Armv7a::new(
            mock_mem,
            &mut state,
            TEST_BASE_ADDRESS,
            DefaultArmSequence::create(),
        )
        .await
        .unwrap();

        // First read will hit expectations
        assert_eq!(
            RegisterValue::from(REG_VALUE),
            armv7a.read_core_reg(RegisterId(15)).await.unwrap()
        );

        // Second read will cache, no new expectations
        assert_eq!(
            RegisterValue::from(REG_VALUE),
            armv7a.read_core_reg(RegisterId(15)).await.unwrap()
        );
    }

    #[pollster::test]
    async fn armv7a_read_core_reg_cpsr() {
        const REG_VALUE: u32 = 0xABCD;

        let mut probe = MockProbe::new();
        let mut state = CortexAState::new();

        // Add expectations
        add_status_expectations(&mut probe, true);
        add_enable_itr_expectations(&mut probe);
        add_read_reg_expectations(&mut probe, 0, 0);
        add_read_fp_count_expectations(&mut probe);

        // Read CPSR
        add_read_cpsr_expectations(&mut probe, REG_VALUE);

        let mock_mem = Box::new(probe) as _;

        let mut armv7a = Armv7a::new(
            mock_mem,
            &mut state,
            TEST_BASE_ADDRESS,
            DefaultArmSequence::create(),
        )
        .await
        .unwrap();

        // First read will hit expectations
        assert_eq!(
            RegisterValue::from(REG_VALUE),
            armv7a.read_core_reg(RegisterId(16)).await.unwrap()
        );

        // Second read will cache, no new expectations
        assert_eq!(
            RegisterValue::from(REG_VALUE),
            armv7a.read_core_reg(RegisterId(16)).await.unwrap()
        );
    }

    #[pollster::test]
    async fn armv7a_halt() {
        const REG_VALUE: u32 = 0xABCD;

        let mut probe = MockProbe::new();
        let mut state = CortexAState::new();

        // Add expectations
        add_status_expectations(&mut probe, false);

        // Write halt request
        let mut dbgdrcr = Dbgdrcr(0);
        dbgdrcr.set_hrq(true);
        probe.expected_write(
            Dbgdrcr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdrcr.into(),
        );

        // Wait for halted
        add_status_expectations(&mut probe, true);

        // Read status
        add_status_expectations(&mut probe, true);
        add_enable_itr_expectations(&mut probe);
        add_read_reg_expectations(&mut probe, 0, 0);
        add_read_fp_count_expectations(&mut probe);

        // Read PC
        add_read_pc_expectations(&mut probe, REG_VALUE);

        let mock_mem = Box::new(probe) as _;

        let mut armv7a = Armv7a::new(
            mock_mem,
            &mut state,
            TEST_BASE_ADDRESS,
            DefaultArmSequence::create(),
        )
        .await
        .unwrap();

        // Verify PC
        assert_eq!(
            REG_VALUE as u64,
            armv7a.halt(Duration::from_millis(100)).await.unwrap().pc
        );
    }

    #[pollster::test]
    async fn armv7a_run() {
        let mut probe = MockProbe::new();
        let mut state = CortexAState::new();

        // Add expectations
        add_status_expectations(&mut probe, true);
        add_enable_itr_expectations(&mut probe);
        add_read_reg_expectations(&mut probe, 0, 0);
        add_read_fp_count_expectations(&mut probe);

        // Writeback r0
        add_set_r0_expectation(&mut probe, 0);

        // Write resume request
        let mut dbgdrcr = Dbgdrcr(0);
        dbgdrcr.set_rrq(true);
        probe.expected_write(
            Dbgdrcr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgdrcr.into(),
        );

        // Wait for running
        add_status_expectations(&mut probe, false);

        // Read status
        add_status_expectations(&mut probe, false);

        let mock_mem = Box::new(probe) as _;

        let mut armv7a = Armv7a::new(
            mock_mem,
            &mut state,
            TEST_BASE_ADDRESS,
            DefaultArmSequence::create(),
        )
        .await
        .unwrap();

        armv7a.run().await.unwrap();
    }

    #[pollster::test]
    async fn armv7a_available_breakpoint_units() {
        const BP_COUNT: u32 = 4;
        let mut probe = MockProbe::new();
        let mut state = CortexAState::new();

        // Add expectations
        add_status_expectations(&mut probe, true);
        add_enable_itr_expectations(&mut probe);
        add_read_reg_expectations(&mut probe, 0, 0);
        add_read_fp_count_expectations(&mut probe);

        // Read breakpoint count
        add_idr_expectations(&mut probe, BP_COUNT);

        let mock_mem = Box::new(probe) as _;

        let mut armv7a = Armv7a::new(
            mock_mem,
            &mut state,
            TEST_BASE_ADDRESS,
            DefaultArmSequence::create(),
        )
        .await
        .unwrap();

        assert_eq!(BP_COUNT, armv7a.available_breakpoint_units().await.unwrap());
    }

    #[pollster::test]
    async fn armv7a_hw_breakpoints() {
        const BP_COUNT: u32 = 4;
        const BP1: u64 = 0x2345;
        const BP2: u64 = 0x8000_0000;
        let mut probe = MockProbe::new();
        let mut state = CortexAState::new();

        // Add expectations
        add_status_expectations(&mut probe, true);
        add_enable_itr_expectations(&mut probe);
        add_read_reg_expectations(&mut probe, 0, 0);
        add_read_fp_count_expectations(&mut probe);

        // Read breakpoint count
        add_idr_expectations(&mut probe, BP_COUNT);

        // Read BP values and controls
        probe.expected_read(
            Dbgbvr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            BP1 as u32,
        );
        probe.expected_read(
            Dbgbcr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            1,
        );

        probe.expected_read(
            Dbgbvr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap() + 4,
            BP2 as u32,
        );
        probe.expected_read(
            Dbgbcr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap() + 4,
            1,
        );

        probe.expected_read(
            Dbgbvr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap() + (2 * 4),
            0,
        );
        probe.expected_read(
            Dbgbcr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap() + (2 * 4),
            0,
        );

        probe.expected_read(
            Dbgbvr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap() + (3 * 4),
            0,
        );
        probe.expected_read(
            Dbgbcr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap() + (3 * 4),
            0,
        );

        let mock_mem = Box::new(probe) as _;

        let mut armv7a = Armv7a::new(
            mock_mem,
            &mut state,
            TEST_BASE_ADDRESS,
            DefaultArmSequence::create(),
        )
        .await
        .unwrap();

        let results = armv7a.hw_breakpoints().await.unwrap();
        assert_eq!(Some(BP1), results[0]);
        assert_eq!(Some(BP2), results[1]);
        assert_eq!(None, results[2]);
        assert_eq!(None, results[3]);
    }

    #[pollster::test]
    async fn armv7a_set_hw_breakpoint() {
        const BP_VALUE: u64 = 0x2345;
        let mut probe = MockProbe::new();
        let mut state = CortexAState::new();

        // Add expectations
        add_status_expectations(&mut probe, true);
        add_enable_itr_expectations(&mut probe);
        add_read_reg_expectations(&mut probe, 0, 0);
        add_read_fp_count_expectations(&mut probe);

        // Update BP value and control
        let mut dbgbcr = Dbgbcr(0);
        // Match on all modes
        dbgbcr.set_hmc(true);
        dbgbcr.set_pmc(0b11);
        // Match on all bytes
        dbgbcr.set_bas(0b1111);
        // Enable
        dbgbcr.set_e(true);

        probe.expected_write(
            Dbgbvr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            BP_VALUE as u32,
        );
        probe.expected_write(
            Dbgbcr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            dbgbcr.into(),
        );

        let mock_mem = Box::new(probe) as _;

        let mut armv7a = Armv7a::new(
            mock_mem,
            &mut state,
            TEST_BASE_ADDRESS,
            DefaultArmSequence::create(),
        )
        .await
        .unwrap();

        armv7a.set_hw_breakpoint(0, BP_VALUE).await.unwrap();
    }

    #[pollster::test]
    async fn armv7a_clear_hw_breakpoint() {
        let mut probe = MockProbe::new();
        let mut state = CortexAState::new();

        // Add expectations
        add_status_expectations(&mut probe, true);
        add_enable_itr_expectations(&mut probe);
        add_read_reg_expectations(&mut probe, 0, 0);
        add_read_fp_count_expectations(&mut probe);

        // Update BP value and control
        probe.expected_write(
            Dbgbvr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            0,
        );
        probe.expected_write(
            Dbgbcr::get_mmio_address_from_base(TEST_BASE_ADDRESS).unwrap(),
            0,
        );

        let mock_mem = Box::new(probe) as _;

        let mut armv7a = Armv7a::new(
            mock_mem,
            &mut state,
            TEST_BASE_ADDRESS,
            DefaultArmSequence::create(),
        )
        .await
        .unwrap();

        armv7a.clear_hw_breakpoint(0).await.unwrap();
    }

    #[pollster::test]
    async fn armv7a_read_word_32() {
        const MEMORY_VALUE: u32 = 0xBA5EBA11;
        const MEMORY_ADDRESS: u64 = 0x12345678;

        let mut probe = MockProbe::new();
        let mut state = CortexAState::new();

        // Add expectations
        add_status_expectations(&mut probe, true);
        add_enable_itr_expectations(&mut probe);
        add_read_reg_expectations(&mut probe, 0, 0);
        add_read_fp_count_expectations(&mut probe);

        // Read memory
        add_read_memory_expectations(&mut probe, MEMORY_ADDRESS, MEMORY_VALUE);

        let mock_mem = Box::new(probe) as _;

        let mut armv7a = Armv7a::new(
            mock_mem,
            &mut state,
            TEST_BASE_ADDRESS,
            DefaultArmSequence::create(),
        )
        .await
        .unwrap();

        assert_eq!(
            MEMORY_VALUE,
            armv7a.read_word_32(MEMORY_ADDRESS).await.unwrap()
        );
    }

    #[pollster::test]
    async fn armv7a_read_word_8() {
        const MEMORY_VALUE: u32 = 0xBA5EBA11;
        const MEMORY_ADDRESS: u64 = 0x12345679;
        const MEMORY_WORD_ADDRESS: u64 = 0x12345678;

        let mut probe = MockProbe::new();
        let mut state = CortexAState::new();

        // Add expectations
        add_status_expectations(&mut probe, true);
        add_enable_itr_expectations(&mut probe);
        add_read_reg_expectations(&mut probe, 0, 0);
        add_read_fp_count_expectations(&mut probe);

        // Read memory
        add_read_memory_expectations(&mut probe, MEMORY_WORD_ADDRESS, MEMORY_VALUE);

        let mock_mem = Box::new(probe) as _;

        let mut armv7a = Armv7a::new(
            mock_mem,
            &mut state,
            TEST_BASE_ADDRESS,
            DefaultArmSequence::create(),
        )
        .await
        .unwrap();

        assert_eq!(0xBA, armv7a.read_word_8(MEMORY_ADDRESS).await.unwrap());
    }
}
