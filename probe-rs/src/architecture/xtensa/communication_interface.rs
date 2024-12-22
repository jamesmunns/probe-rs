//! Xtensa Debug Module Communication

use std::{
    collections::HashMap,
    ops::Range,
    time::{Duration},
};
use web_time::Instant;

use probe_rs_target::MemoryRange;

use crate::{
    architecture::xtensa::{
        arch::{instruction::Instruction, CpuRegister, Register, SpecialRegister},
        xdm::{DebugStatus, XdmState},
    },
    probe::{DebugProbeError, DeferredResultIndex, JTAGAccess},
    BreakpointCause, Error as ProbeRsError, HaltReason, MemoryInterface,
};

use super::xdm::{Error as XdmError, Xdm};

/// Possible Xtensa errors
#[derive(thiserror::Error, Debug, docsplay::Display)]
pub enum XtensaError {
    /// An error originating from the DebugProbe occurred.
    DebugProbe(#[from] DebugProbeError),

    /// Xtensa debug module error.
    XdmError(#[from] XdmError),

    /// The core is not enabled.
    CoreDisabled,

    /// The operation has timed out.
    // TODO: maybe we could be a bit more specific
    Timeout,

    /// The connected target is not an Xtensa device.
    NoXtensaTarget,

    /// The requested register is not available.
    RegisterNotAvailable,

    /// The result index of a batched command is not available.
    BatchedResultNotAvailable,
}

impl From<XtensaError> for ProbeRsError {
    fn from(err: XtensaError) -> Self {
        match err {
            XtensaError::DebugProbe(e) => e.into(),
            other => ProbeRsError::Xtensa(other),
        }
    }
}

#[derive(Clone, Copy)]
#[allow(unused)]
enum DebugLevel {
    L2 = 2,
    L3 = 3,
    L4 = 4,
    L5 = 5,
    L6 = 6,
    L7 = 7,
}

impl DebugLevel {
    pub fn pc(self) -> SpecialRegister {
        match self {
            DebugLevel::L2 => SpecialRegister::Epc2,
            DebugLevel::L3 => SpecialRegister::Epc3,
            DebugLevel::L4 => SpecialRegister::Epc4,
            DebugLevel::L5 => SpecialRegister::Epc5,
            DebugLevel::L6 => SpecialRegister::Epc6,
            DebugLevel::L7 => SpecialRegister::Epc7,
        }
    }

    pub fn ps(self) -> SpecialRegister {
        match self {
            DebugLevel::L2 => SpecialRegister::Eps2,
            DebugLevel::L3 => SpecialRegister::Eps3,
            DebugLevel::L4 => SpecialRegister::Eps4,
            DebugLevel::L5 => SpecialRegister::Eps5,
            DebugLevel::L6 => SpecialRegister::Eps6,
            DebugLevel::L7 => SpecialRegister::Eps7,
        }
    }
}

/// Xtensa interface state.
// FIXME: This struct is a weird mix between core state, debug module state and core configuration.
pub(super) struct XtensaInterfaceState {
    /// Pairs of (register, read handle). The value is optional where None means "being restored"
    saved_registers: HashMap<Register, Option<DeferredResultIndex>>,

    /// Whether the core is halted.
    // This roughly relates to Core Debug States (true = Running, false = [Stopped, Stepping])
    is_halted: bool,

    /// The number of hardware breakpoints the target supports. CPU-specific configuration value.
    hw_breakpoint_num: u32,

    /// The interrupt level at which debug exceptions are generated. CPU-specific configuration value.
    debug_level: DebugLevel,

    /// The address range for which we should not use LDDR32.P/SDDR32.P instructions.
    slow_memory_access_ranges: Vec<Range<u64>>,
}

impl Default for XtensaInterfaceState {
    fn default() -> Self {
        Self {
            saved_registers: Default::default(),
            is_halted: false,

            // FIXME: these are per-chip configuration parameters
            hw_breakpoint_num: 2,
            debug_level: DebugLevel::L6,
            slow_memory_access_ranges: vec![],
        }
    }
}

/// Debug module and transport state.
#[derive(Default)]
pub struct XtensaDebugInterfaceState {
    interface_state: XtensaInterfaceState,
    xdm_state: XdmState,
}

/// The higher level of the XDM functionality.
// TODO: this includes core state and CPU configuration that don't exactly belong
// here but one layer up.
pub struct XtensaCommunicationInterface<'probe> {
    /// The Xtensa debug module
    pub(crate) xdm: Xdm<'probe>,
    state: &'probe mut XtensaInterfaceState,
}

impl<'probe> XtensaCommunicationInterface<'probe> {
    /// Create the Xtensa communication interface using the underlying probe driver
    pub fn new(
        probe: &'probe mut dyn JTAGAccess,
        state: &'probe mut XtensaDebugInterfaceState,
    ) -> Self {
        let XtensaDebugInterfaceState {
            interface_state,
            xdm_state,
        } = state;
        let xdm = Xdm::new(probe, xdm_state);

        Self {
            xdm,
            state: interface_state,
        }
    }

    /// Set the range of addresses for which we should not use LDDR32.P/SDDR32.P instructions.
    pub fn add_slow_memory_access_range(&mut self, range: Range<u64>) {
        self.state.slow_memory_access_ranges.push(range);
    }

    /// Read the targets IDCODE.
    pub async fn read_idcode(&mut self) -> Result<u32, XtensaError> {
        self.xdm.read_idcode().await
    }

    /// Enter debug mode.
    pub async fn enter_debug_mode(&mut self) -> Result<(), XtensaError> {
        self.xdm.enter_debug_mode().await?;

        self.state.is_halted = self.xdm.status().await?.stopped();

        Ok(())
    }

    pub(crate) async fn leave_debug_mode(&mut self) -> Result<(), XtensaError> {
        if self.xdm.status().await?.stopped() {
            self.restore_registers().await?;
            self.resume_core().await?;
        }
        self.xdm.leave_ocd_mode().await?;

        tracing::debug!("Left OCD mode");

        Ok(())
    }

    /// Returns the number of hardware breakpoints the target supports.
    ///
    /// On the Xtensa architecture this is the `NIBREAK` configuration parameter.
    pub fn available_breakpoint_units(&self) -> u32 {
        self.state.hw_breakpoint_num
    }

    /// Returns whether the core is halted.
    pub async fn core_halted(&mut self) -> Result<bool, XtensaError> {
        if !self.state.is_halted {
            self.state.is_halted = self.xdm.status().await?.stopped();
        }

        Ok(self.state.is_halted)
    }

    /// Waits until the core is halted.
    ///
    /// This function lowers the interrupt level to allow halting on debug exceptions.
    pub async fn wait_for_core_halted(&mut self, timeout: Duration) -> Result<(), XtensaError> {
        // Wait until halted state is active again.
        let start = Instant::now();

        while !self.core_halted().await? {
            if start.elapsed() >= timeout {
                return Err(XtensaError::Timeout);
            }
            // Wait a bit before polling again.
            std::thread::sleep(Duration::from_millis(1));
        }

        Ok(())
    }

    /// Halts the core.
    pub(crate) async fn halt(&mut self, timeout: Duration) -> Result<(), XtensaError> {
        self.xdm.schedule_halt().await;
        self.wait_for_core_halted(timeout).await?;
        Ok(())
    }

    /// Halts the core and returns `true` if the core was running before the halt.
    pub(crate) async fn halt_with_previous(
        &mut self,
        timeout: Duration,
    ) -> Result<bool, XtensaError> {
        let was_running = if self.state.is_halted {
            // Core is already halted, we don't need to do anything.
            false
        } else {
            // If we have not halted the core, it may still be halted on a breakpoint, for example.
            // Let's check status.
            let status_idx = self.xdm.schedule_read_nexus_register::<DebugStatus>().await;
            self.halt(timeout).await?;
            let before_status =
                DebugStatus(self.xdm.read_deferred_result(status_idx).await?.into_u32());

            !before_status.stopped()
        };

        Ok(was_running)
    }

    async fn fast_halted_access_start(&mut self) -> Result<bool, XtensaError> {
        if self.state.is_halted {
            // Core is already halted, we don't need to do anything.
            return Ok(false);
        }

        // If we have not halted the core, it may still be halted on a breakpoint, for example.
        // Let's check status.
        let status_idx = self.xdm.schedule_read_nexus_register::<DebugStatus>().await;

        // Queue up halting.
        self.xdm.schedule_halt().await;

        // We will need to check if we managed to halt the core.
        let _is_halted_idx = self.xdm.schedule_read_nexus_register::<DebugStatus>().await;
        self.state.is_halted = true;

        // Execute the operation while the core is presumed halted. If it is not, we will have
        // various errors, but we will retry the operation.
        // let result = op(self);

        // If the core was running, resume it.
        let before_status =
            DebugStatus(self.xdm.read_deferred_result(status_idx).await?.into_u32());
        if !before_status.stopped() {
            self.resume_core().await?;
        }

        // If we did not manage to halt the core at once, let's retry using the slow path.
        // let after_status = DebugStatus(
        //     self.xdm
        //         .read_deferred_result(is_halted_idx)
        //         .await?
        //         .into_u32(),
        // );

        // if after_status.stopped() {
        //     return result;
        // }
        self.state.is_halted = false;
        let was_running = self.halt_with_previous(Duration::from_millis(100)).await?;
        Ok(was_running)
    }

    async fn fast_halted_access_end(&mut self, was_running: bool) -> Result<(), XtensaError> {
        if was_running {
            self.resume_core().await?;
        }

        Ok(())
    }

    /// Steps the core by one instruction.
    pub async fn step(&mut self) -> Result<(), XtensaError> {
        self.schedule_write_register(ICountLevel(self.state.debug_level as u32))
            .await?;

        // An exception is generated at the beginning of an instruction that would overflow ICOUNT.
        self.schedule_write_register(ICount(-2_i32 as u32)).await?;

        self.resume_core().await?;
        self.wait_for_core_halted(Duration::from_millis(100))
            .await?;

        // Avoid stopping again
        self.schedule_write_register(ICountLevel(self.state.debug_level as u32 + 1))
            .await?;

        Ok(())
    }

    /// Resumes program execution.
    pub async fn resume_core(&mut self) -> Result<(), XtensaError> {
        tracing::debug!("Resuming core");
        self.state.is_halted = false;
        self.xdm.resume().await?;

        Ok(())
    }

    async fn schedule_read_cpu_register(&mut self, register: CpuRegister) -> DeferredResultIndex {
        self.xdm
            .schedule_execute_instruction(Instruction::Wsr(SpecialRegister::Ddr, register))
            .await;
        self.xdm.schedule_read_ddr().await
    }

    async fn schedule_read_special_register(
        &mut self,
        register: SpecialRegister,
    ) -> Result<DeferredResultIndex, XtensaError> {
        let save_key = Box::pin(self.save_register(CpuRegister::A3)).await?;

        // Read special register into the scratch register
        self.xdm
            .schedule_execute_instruction(Instruction::Rsr(register, CpuRegister::A3))
            .await;

        let reader = self.schedule_read_cpu_register(CpuRegister::A3).await;

        Box::pin(self.restore_register(save_key)).await?;

        Ok(reader)
    }

    async fn schedule_write_special_register(
        &mut self,
        register: SpecialRegister,
        value: u32,
    ) -> Result<(), XtensaError> {
        tracing::debug!("Writing special register: {:?}", register);
        let save_key = Box::pin(self.save_register(CpuRegister::A3)).await?;

        self.xdm.schedule_write_ddr(value).await;

        // DDR -> scratch
        self.xdm
            .schedule_execute_instruction(Instruction::Rsr(SpecialRegister::Ddr, CpuRegister::A3))
            .await;

        // scratch -> target special register
        self.xdm
            .schedule_execute_instruction(Instruction::Wsr(register, CpuRegister::A3))
            .await;

        self.restore_register(save_key).await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn schedule_write_cpu_register(
        &mut self,
        register: CpuRegister,
        value: u32,
    ) -> Result<(), XtensaError> {
        tracing::debug!("Writing {:x} to register: {:?}", value, register);

        self.xdm.schedule_write_ddr(value).await;
        self.xdm
            .schedule_execute_instruction(Instruction::Rsr(SpecialRegister::Ddr, register))
            .await;

        Ok(())
    }

    /// Read a register.
    pub async fn read_register<R: TypedRegister>(&mut self) -> Result<R, XtensaError> {
        let value = self.read_register_untyped(R::register()).await?;

        Ok(R::from_u32(value))
    }

    /// Schedules reading a register.
    pub async fn schedule_read_register<R: TypedRegister>(
        &mut self,
    ) -> Result<DeferredResultIndex, XtensaError> {
        self.schedule_read_register_untyped(R::register()).await
    }

    /// Write a register.
    pub async fn write_register<R: TypedRegister>(&mut self, reg: R) -> Result<(), XtensaError> {
        self.write_register_untyped(R::register(), reg.as_u32())
            .await?;

        Ok(())
    }

    /// Schedules writing a register.
    pub async fn schedule_write_register<R: TypedRegister>(
        &mut self,
        reg: R,
    ) -> Result<(), XtensaError> {
        self.schedule_write_register_untyped(R::register(), reg.as_u32())
            .await?;

        Ok(())
    }

    /// Schedules reading a register.
    pub async fn schedule_read_register_untyped(
        &mut self,
        register: impl Into<Register>,
    ) -> Result<DeferredResultIndex, XtensaError> {
        match register.into() {
            Register::Cpu(register) => Ok(self.schedule_read_cpu_register(register).await),
            Register::Special(register) => self.schedule_read_special_register(register).await,
            Register::CurrentPc => {
                self.schedule_read_special_register(self.state.debug_level.pc())
                    .await
            }
            Register::CurrentPs => {
                self.schedule_read_special_register(self.state.debug_level.ps())
                    .await
            }
        }
    }

    /// Read a register.
    pub async fn read_register_untyped(
        &mut self,
        register: impl Into<Register>,
    ) -> Result<u32, XtensaError> {
        let reader = self.schedule_read_register_untyped(register).await?;
        Ok(self.xdm.read_deferred_result(reader).await?.into_u32())
    }

    /// Schedules writing a register.
    pub async fn schedule_write_register_untyped(
        &mut self,
        register: impl Into<Register>,
        value: u32,
    ) -> Result<(), XtensaError> {
        Box::pin(async {
            match register.into() {
                Register::Cpu(register) => self.schedule_write_cpu_register(register, value).await,
                Register::Special(register) => {
                    self.schedule_write_special_register(register, value).await
                }
                Register::CurrentPc => {
                    self.schedule_write_special_register(self.state.debug_level.pc(), value)
                        .await
                }
                Register::CurrentPs => {
                    self.schedule_write_special_register(self.state.debug_level.ps(), value)
                        .await
                }
            }
        })
        .await
    }

    /// Write a register.
    pub async fn write_register_untyped(
        &mut self,
        register: impl Into<Register>,
        value: u32,
    ) -> Result<(), XtensaError> {
        self.schedule_write_register_untyped(register, value)
            .await?;
        self.xdm.execute().await
    }

    #[tracing::instrument(skip(self, register), fields(register))]
    async fn save_register(
        &mut self,
        register: impl Into<Register>,
    ) -> Result<Option<Register>, XtensaError> {
        let register = register.into();

        tracing::Span::current().record("register", format!("{register:?}"));

        if matches!(
            register,
            Register::Special(
                SpecialRegister::Ddr | SpecialRegister::ICount | SpecialRegister::ICountLevel
            )
        ) {
            // Avoid saving some registers
            return Ok(None);
        }

        let is_saved = self.state.saved_registers.contains_key(&register);

        if is_saved {
            return Ok(None);
        }

        tracing::debug!("Saving register: {:?}", register);
        let value = self.schedule_read_register_untyped(register).await?;
        self.state.saved_registers.insert(register, Some(value));

        Ok(Some(register))
    }

    #[tracing::instrument(skip(self))]
    async fn restore_register(&mut self, key: Option<Register>) -> Result<(), XtensaError> {
        let Some(key) = key else {
            return Ok(());
        };

        tracing::debug!("Restoring register: {:?}", key);

        // Remove the result early, so an error here will not cause a panic in `restore_registers`.
        if let Some(value) = self.state.saved_registers.remove(&key) {
            let reader = value.unwrap();
            let value = self.xdm.read_deferred_result(reader).await?.into_u32();

            self.schedule_write_register_untyped(key, value).await?;
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub(super) async fn restore_registers(&mut self) -> Result<(), XtensaError> {
        tracing::debug!("Restoring registers");

        // Clone the list of saved registers so we can iterate over it, but code may still save
        // new registers. We can't take it otherwise the restore loop would unnecessarily save
        // registers.
        // Currently, restoring registers may only use the scratch register which is already saved
        // if we access special registers. This means the register list won't actually change in the
        // next loop.
        let dirty_regs = self
            .state
            .saved_registers
            .keys()
            .copied()
            .collect::<Vec<_>>();

        let dirty_count = dirty_regs.len();

        let mut restore_scratch = None;

        for register in dirty_regs {
            let reader = self
                .state
                .saved_registers
                .get_mut(&register)
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    panic!(
                        "Failed to get original value of dirty register {:?}. This is a bug.",
                        register
                    )
                });
            let value = self.xdm.read_deferred_result(reader).await?.into_u32();

            if register == Register::Cpu(CpuRegister::A3) {
                // We need to handle the scratch register (A3) separately as restoring a special
                // register will overwrite it.
                restore_scratch = Some(value);
            } else {
                self.schedule_write_register_untyped(register, value)
                    .await?;
            }
        }

        if self.state.saved_registers.len() != dirty_count {
            // The scratch register wasn't saved before, but has to be restored now. This case should
            // not currently be reachable.
            // TODO: we shouldn't special-case the A3 register, I think
            if let Some(reader) = self
                .state
                .saved_registers
                .get_mut(&Register::Cpu(CpuRegister::A3))
            {
                if let Some(reader) = reader.take() {
                    let value = self.xdm.read_deferred_result(reader).await?.into_u32();

                    restore_scratch = Some(value);
                }
            }
        }

        if let Some(value) = restore_scratch {
            self.schedule_write_register_untyped(CpuRegister::A3, value)
                .await?;
        }

        self.state.saved_registers.clear();
        Ok(())
    }

    fn memory_access_for(&self, address: u64, len: usize) -> Box<dyn MemoryAccess> {
        let use_slow_access = self
            .state
            .slow_memory_access_ranges
            .iter()
            .any(|r| r.intersects_range(&(address..address + len as u64)));

        if use_slow_access {
            Box::new(SlowMemoryAccess::new())
        } else {
            Box::new(FastMemoryAccess::new())
        }
    }

    async fn read_memory(&mut self, address: u64, dst: &mut [u8]) -> Result<(), XtensaError> {
        tracing::debug!("Reading {} bytes from address {:08x}", dst.len(), address);
        if dst.is_empty() {
            return Ok(());
        }

        let mut memory_access = self.memory_access_for(address, dst.len());

        let was_running = self.fast_halted_access_start().await?;
        memory_access.save_scratch_registers(self).await?;
        self.read_memory_impl(memory_access.as_mut(), address, dst)
            .await?;
        memory_access.restore_scratch_registers(self).await?;

        if was_running {
            self.fast_halted_access_end(was_running).await?;
        }

        Ok(())
    }

    async fn read_memory_impl(
        &mut self,
        memory_access: &mut dyn MemoryAccess,
        address: u64,
        mut dst: &mut [u8],
    ) -> Result<(), XtensaError> {
        memory_access
            .load_initial_address_for_read(self, address as u32 & !0x3)
            .await?;

        let mut to_read = dst.len();

        // Let's assume we can just do 32b reads, so let's do some pre-massaging on unaligned reads
        let first_read = if address % 4 != 0 {
            let offset = address as usize % 4;

            // Avoid executing another read if we only have to read a single word
            let first_read = if offset + to_read <= 4 {
                memory_access.read_one(self).await?
            } else {
                memory_access.read_one_and_continue(self).await?
            };

            let bytes_to_copy = (4 - offset).min(to_read);

            to_read -= bytes_to_copy;

            Some((first_read, offset, bytes_to_copy))
        } else {
            None
        };

        let mut aligned_reads = vec![];
        if to_read > 0 {
            let words = to_read.div_ceil(4);

            for _ in 0..words - 1 {
                aligned_reads.push(memory_access.read_one_and_continue(self).await?);
            }
            aligned_reads.push(memory_access.read_one(self).await?);
        };

        memory_access.restore_scratch_registers(self).await?;

        if let Some((read, offset, bytes_to_copy)) = first_read {
            let word = self
                .xdm
                .read_deferred_result(read)
                .await?
                .into_u32()
                .to_le_bytes();

            dst[..bytes_to_copy].copy_from_slice(&word[offset..][..bytes_to_copy]);
            dst = &mut dst[bytes_to_copy..];
        }

        for read in aligned_reads {
            let word = self
                .xdm
                .read_deferred_result(read)
                .await?
                .into_u32()
                .to_le_bytes();

            let bytes = dst.len().min(4);

            dst[..bytes].copy_from_slice(&word[..bytes]);
            dst = &mut dst[bytes..];
        }

        Ok(())
    }

    pub(crate) async fn write_memory(
        &mut self,
        address: u64,
        data: &[u8],
    ) -> Result<(), XtensaError> {
        tracing::debug!("Writing {} bytes to address {:08x}", data.len(), address);
        if data.is_empty() {
            return Ok(());
        }

        let mut memory_access = self.memory_access_for(address, data.len());

        let was_running = self.fast_halted_access_start().await?;
        memory_access.save_scratch_registers(self).await?;
        self.write_memory_impl(memory_access.as_mut(), address, data)
            .await?;
        memory_access.restore_scratch_registers(self).await?;

        if was_running {
            self.fast_halted_access_end(was_running).await?;
        }
        Ok(())
    }

    async fn write_memory_unaligned8(
        &mut self,
        memory_access: &mut dyn MemoryAccess,
        address: u32,
        data: &[u8],
    ) -> Result<(), XtensaError> {
        if data.is_empty() {
            return Ok(());
        }

        let offset = address as usize % 4;
        let aligned_address = address & !0x3;

        assert!(
            offset + data.len() <= 4,
            "Trying to write data crossing a word boundary"
        );

        // Avoid reading back if we have a complete word
        let data = if offset == 0 && data.len() == 4 {
            data.try_into().unwrap()
        } else {
            // Read the aligned word
            let mut word = [0; 4];
            self.read_memory_impl(memory_access, aligned_address as u64, &mut word)
                .await?;

            // Replace the written bytes. This will also panic if the input is crossing a word boundary
            word[offset..][..data.len()].copy_from_slice(data);

            word
        };

        // Write the word back
        memory_access
            .load_initial_address_for_write(self, aligned_address)
            .await?;
        memory_access
            .write_one(self, u32::from_le_bytes(data))
            .await
    }

    async fn write_memory_impl(
        &mut self,
        memory_access: &mut dyn MemoryAccess,
        address: u64,
        mut buffer: &[u8],
    ) -> Result<(), XtensaError> {
        let mut addr = address as u32;

        // We store the unaligned head of the data separately
        if addr % 4 != 0 {
            let unaligned_bytes = (4 - (addr % 4) as usize).min(buffer.len());

            self.write_memory_unaligned8(memory_access, addr, &buffer[..unaligned_bytes])
                .await?;

            buffer = &buffer[unaligned_bytes..];
            addr += unaligned_bytes as u32;
        }

        if buffer.len() > 4 {
            memory_access
                .load_initial_address_for_write(self, addr)
                .await?;

            let mut chunks = buffer.chunks_exact(4);
            for chunk in chunks.by_ref() {
                let mut word = [0; 4];
                word[..].copy_from_slice(chunk);
                let word = u32::from_le_bytes(word);

                memory_access.write_one(self, word).await?;

                addr += 4;
            }

            buffer = chunks.remainder();
        }

        // We store the narrow tail of the data separately
        if !buffer.is_empty() {
            self.write_memory_unaligned8(memory_access, addr, buffer)
                .await?;
        }

        // TODO: implement cache flushing on CPUs that need it.

        Ok(())
    }

    pub(crate) async fn reset_and_halt(&mut self, timeout: Duration) -> Result<(), XtensaError> {
        self.clear_register_cache();
        self.xdm.reset_and_halt().await?;
        self.wait_for_core_halted(timeout).await?;

        // TODO: this is only necessary to run code, so this might not be the best place
        // Make sure the CPU is in a known state and is able to run code we download.
        self.write_register({
            let mut ps = ProgramStatus(0);
            ps.set_intlevel(0);
            ps.set_user_mode(true);
            ps.set_woe(true);
            ps
        })
        .await?;

        Ok(())
    }

    pub(crate) fn clear_register_cache(&mut self) {
        self.state.saved_registers.clear();
    }
}

/// DataType
///
/// # Safety
/// Don't implement this trait
unsafe trait DataType: Sized {}
unsafe impl DataType for u8 {}
unsafe impl DataType for u16 {}
unsafe impl DataType for u32 {}
unsafe impl DataType for u64 {}

fn as_bytes<T: DataType>(data: &[T]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(data.as_ptr() as *mut u8, std::mem::size_of_val(data)) }
}

fn as_bytes_mut<T: DataType>(data: &mut [T]) -> &mut [u8] {
    unsafe {
        std::slice::from_raw_parts_mut(data.as_mut_ptr() as *mut u8, std::mem::size_of_val(data))
    }
}

#[async_trait::async_trait(?Send)]
impl MemoryInterface for XtensaCommunicationInterface<'_> {
    async fn read(&mut self, address: u64, dst: &mut [u8]) -> Result<(), crate::Error> {
        self.read_memory(address, dst).await?;

        Ok(())
    }

    async fn supports_native_64bit_access(&mut self) -> bool {
        false
    }

    async fn read_word_64(&mut self, address: u64) -> Result<u64, crate::Error> {
        let mut out = [0; 8];
        self.read(address, &mut out).await?;

        Ok(u64::from_le_bytes(out))
    }

    async fn read_word_32(&mut self, address: u64) -> Result<u32, crate::Error> {
        let mut out = [0; 4];
        self.read(address, &mut out).await?;

        Ok(u32::from_le_bytes(out))
    }

    async fn read_word_16(&mut self, address: u64) -> Result<u16, crate::Error> {
        let mut out = [0; 2];
        self.read(address, &mut out).await?;

        Ok(u16::from_le_bytes(out))
    }

    async fn read_word_8(&mut self, address: u64) -> Result<u8, crate::Error> {
        let mut out = 0;
        self.read(address, std::slice::from_mut(&mut out)).await?;
        Ok(out)
    }

    async fn read_64(&mut self, address: u64, data: &mut [u64]) -> Result<(), crate::Error> {
        self.read_8(address, as_bytes_mut(data)).await
    }

    async fn read_32(&mut self, address: u64, data: &mut [u32]) -> Result<(), crate::Error> {
        self.read_8(address, as_bytes_mut(data)).await
    }

    async fn read_16(&mut self, address: u64, data: &mut [u16]) -> Result<(), crate::Error> {
        self.read_8(address, as_bytes_mut(data)).await
    }

    async fn read_8(&mut self, address: u64, data: &mut [u8]) -> Result<(), crate::Error> {
        self.read(address, data).await
    }

    async fn write(&mut self, address: u64, data: &[u8]) -> Result<(), crate::Error> {
        self.write_memory(address, data).await?;

        Ok(())
    }

    async fn write_word_64(&mut self, address: u64, data: u64) -> Result<(), crate::Error> {
        self.write(address, &data.to_le_bytes()).await
    }

    async fn write_word_32(&mut self, address: u64, data: u32) -> Result<(), crate::Error> {
        self.write(address, &data.to_le_bytes()).await
    }

    async fn write_word_16(&mut self, address: u64, data: u16) -> Result<(), crate::Error> {
        self.write(address, &data.to_le_bytes()).await
    }

    async fn write_word_8(&mut self, address: u64, data: u8) -> Result<(), crate::Error> {
        self.write(address, &[data]).await
    }

    async fn write_64(&mut self, address: u64, data: &[u64]) -> Result<(), crate::Error> {
        self.write_8(address, as_bytes(data)).await
    }

    async fn write_32(&mut self, address: u64, data: &[u32]) -> Result<(), crate::Error> {
        self.write_8(address, as_bytes(data)).await
    }

    async fn write_16(&mut self, address: u64, data: &[u16]) -> Result<(), crate::Error> {
        self.write_8(address, as_bytes(data)).await
    }

    async fn write_8(&mut self, address: u64, data: &[u8]) -> Result<(), crate::Error> {
        self.write(address, data).await
    }

    async fn supports_8bit_transfers(&self) -> Result<bool, crate::Error> {
        Ok(true)
    }

    async fn flush(&mut self) -> Result<(), crate::Error> {
        Ok(())
    }
}

/// An Xtensa core register
pub trait TypedRegister: Copy {
    /// Returns the register ID.
    fn register() -> Register;

    /// Creates a new register from the given value.
    fn from_u32(value: u32) -> Self;

    /// Returns the register value.
    fn as_u32(self) -> u32;
}

macro_rules! u32_register {
    ($name:ident, $register:expr) => {
        impl TypedRegister for $name {
            fn register() -> Register {
                Register::from($register)
            }

            fn from_u32(value: u32) -> Self {
                Self(value)
            }

            fn as_u32(self) -> u32 {
                self.0
            }
        }
    };
}

bitfield::bitfield! {
    /// The `DEBUGCAUSE` register.
    #[derive(Copy, Clone)]
    pub struct DebugCause(u32);
    impl Debug;

    /// Instruction counter exception
    pub icount_exception,    set_icount_exception   : 0;

    /// Instruction breakpoint exception
    pub ibreak_exception,    set_ibreak_exception   : 1;

    /// Data breakpoint (watchpoint) exception
    pub dbreak_exception,    set_dbreak_exception   : 2;

    /// Break instruction exception
    pub break_instruction,   set_break_instruction  : 3;

    /// Narrow Break instruction exception
    pub break_n_instruction, set_break_n_instruction: 4;

    /// Debug interrupt exception
    pub debug_interrupt,     set_debug_interrupt    : 5;

    /// Data breakpoint number
    pub dbreak_num,          set_dbreak_num         : 11, 8;
}
u32_register!(DebugCause, SpecialRegister::DebugCause);

impl DebugCause {
    /// Returns the reason why the core is halted.
    pub fn halt_reason(&self) -> HaltReason {
        let is_icount_exception = self.icount_exception();
        let is_ibreak_exception = self.ibreak_exception();
        let is_break_instruction = self.break_instruction();
        let is_break_n_instruction = self.break_n_instruction();
        let is_dbreak_exception = self.dbreak_exception();
        let is_debug_interrupt = self.debug_interrupt();

        let is_breakpoint = is_break_instruction || is_break_n_instruction;

        let count = is_icount_exception as u8
            + is_ibreak_exception as u8
            + is_break_instruction as u8
            + is_break_n_instruction as u8
            + is_dbreak_exception as u8
            + is_debug_interrupt as u8;

        if count > 1 {
            tracing::debug!("DebugCause: {:?}", self);

            // We cannot identify why the chip halted,
            // it could be for multiple reasons.

            // For debuggers, it's important to know if
            // the core halted because of a breakpoint.
            // Because of this, we still return breakpoint
            // even if other reasons are possible as well.
            if is_breakpoint {
                HaltReason::Breakpoint(BreakpointCause::Unknown)
            } else {
                HaltReason::Multiple
            }
        } else if is_icount_exception {
            HaltReason::Step
        } else if is_ibreak_exception {
            HaltReason::Breakpoint(BreakpointCause::Hardware)
        } else if is_breakpoint {
            HaltReason::Breakpoint(BreakpointCause::Software)
        } else if is_dbreak_exception {
            HaltReason::Watchpoint
        } else if is_debug_interrupt {
            HaltReason::Request
        } else {
            HaltReason::Unknown
        }
    }
}

bitfield::bitfield! {
    /// The `PS` (Program Status) register.
    ///
    /// The physical register depends on the debug level.
    #[derive(Copy, Clone)]
    pub struct ProgramStatus(u32);
    impl Debug;

    /// Interrupt level disable
    pub intlevel,  set_intlevel : 3, 0;

    /// Exception mode
    pub excm,      set_excm     : 4;

    /// User mode
    pub user_mode, set_user_mode: 5;

    /// Privilege level (when using the MMU option)
    pub ring,      set_ring     : 7, 6;

    /// Old window base
    pub owb,       set_owb      : 11, 8;

    /// Call increment
    pub callinc,   set_callinc  : 17, 16;

    /// Window overflow-detection enable
    pub woe,       set_woe      : 18;
}
u32_register!(ProgramStatus, Register::CurrentPs);

/// The `IBREAKEN` (Instruction Breakpoint Enable) register.
#[derive(Copy, Clone, Debug)]
pub struct IBreakEn(pub u32);
u32_register!(IBreakEn, SpecialRegister::IBreakEnable);

/// The `ICOUNT` (Instruction Counter) register.
#[derive(Copy, Clone, Debug)]
pub struct ICount(pub u32);
u32_register!(ICount, SpecialRegister::ICount);

/// The `ICOUNTLEVEL` (Instruction Count Level) register.
#[derive(Copy, Clone, Debug)]
pub struct ICountLevel(pub u32);
u32_register!(ICountLevel, SpecialRegister::ICountLevel);

/// The Program Counter register.
#[derive(Copy, Clone, Debug)]
pub struct ProgramCounter(pub u32);
u32_register!(ProgramCounter, Register::CurrentPc);

#[async_trait::async_trait(?Send)]
trait MemoryAccess {
    async fn save_scratch_registers(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
    ) -> Result<(), XtensaError>;

    async fn restore_scratch_registers(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
    ) -> Result<(), XtensaError>;

    async fn load_initial_address_for_read(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
        address: u32,
    ) -> Result<(), XtensaError>;
    async fn load_initial_address_for_write(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
        address: u32,
    ) -> Result<(), XtensaError>;

    async fn read_one(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
    ) -> Result<DeferredResultIndex, XtensaError>;

    async fn read_one_and_continue(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
    ) -> Result<DeferredResultIndex, XtensaError>;

    async fn write_one(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
        data: u32,
    ) -> Result<(), XtensaError>;
}

/// Memory access using LDDR32.P and SDDR32.P instructions.
struct FastMemoryAccess {
    a3: Option<Register>,
}

impl FastMemoryAccess {
    fn new() -> Self {
        Self { a3: None }
    }
}

#[async_trait::async_trait(?Send)]
impl MemoryAccess for FastMemoryAccess {
    async fn save_scratch_registers(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
    ) -> Result<(), XtensaError> {
        self.a3 = interface.save_register(CpuRegister::A3).await?;
        Ok(())
    }

    async fn restore_scratch_registers(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
    ) -> Result<(), XtensaError> {
        interface.restore_register(self.a3.take()).await
    }

    async fn load_initial_address_for_read(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
        address: u32,
    ) -> Result<(), XtensaError> {
        // Write aligned address to the scratch register
        interface
            .schedule_write_cpu_register(CpuRegister::A3, address)
            .await?;

        // Read from address in the scratch register
        interface
            .xdm
            .schedule_execute_instruction(Instruction::Lddr32P(CpuRegister::A3))
            .await;

        Ok(())
    }

    async fn load_initial_address_for_write(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
        address: u32,
    ) -> Result<(), XtensaError> {
        interface
            .schedule_write_cpu_register(CpuRegister::A3, address)
            .await?;
        interface
            .xdm
            .schedule_write_instruction(Instruction::Sddr32P(CpuRegister::A3))
            .await;

        Ok(())
    }

    async fn write_one(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
        data: u32,
    ) -> Result<(), XtensaError> {
        interface.xdm.schedule_write_ddr_and_execute(data).await;
        Ok(())
    }

    async fn read_one(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
    ) -> Result<DeferredResultIndex, XtensaError> {
        Ok(interface.xdm.schedule_read_ddr().await)
    }

    async fn read_one_and_continue(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
    ) -> Result<DeferredResultIndex, XtensaError> {
        Ok(interface.xdm.schedule_read_ddr_and_execute().await)
    }
}

/// Memory access without LDDR32.P and SDDR32.P instructions.
struct SlowMemoryAccess {
    a3: Option<Register>,
    a4: Option<Register>,
    current_address: u32,
}
impl SlowMemoryAccess {
    fn new() -> Self {
        Self {
            a3: None,
            a4: None,
            current_address: 0,
        }
    }
}

#[async_trait::async_trait(?Send)]
impl MemoryAccess for SlowMemoryAccess {
    async fn save_scratch_registers(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
    ) -> Result<(), XtensaError> {
        self.a3 = interface.save_register(CpuRegister::A3).await?;
        self.a4 = interface.save_register(CpuRegister::A4).await?;
        Ok(())
    }

    async fn restore_scratch_registers(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
    ) -> Result<(), XtensaError> {
        interface.restore_register(self.a4.take()).await?;
        interface.restore_register(self.a3.take()).await?;
        Ok(())
    }

    async fn load_initial_address_for_read(
        &mut self,
        _interface: &mut XtensaCommunicationInterface,
        address: u32,
    ) -> Result<(), XtensaError> {
        self.current_address = address;

        Ok(())
    }

    async fn load_initial_address_for_write(
        &mut self,
        _interface: &mut XtensaCommunicationInterface,
        address: u32,
    ) -> Result<(), XtensaError> {
        self.current_address = address;

        Ok(())
    }

    async fn read_one(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
    ) -> Result<DeferredResultIndex, XtensaError> {
        interface
            .schedule_write_cpu_register(CpuRegister::A3, self.current_address)
            .await?;
        self.current_address += 4;

        interface
            .xdm
            .schedule_execute_instruction(Instruction::L32I(CpuRegister::A3, CpuRegister::A4, 0))
            .await;

        Ok(interface.schedule_read_cpu_register(CpuRegister::A4).await)
    }

    async fn read_one_and_continue(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
    ) -> Result<DeferredResultIndex, XtensaError> {
        self.read_one(interface).await
    }

    async fn write_one(
        &mut self,
        interface: &mut XtensaCommunicationInterface,
        data: u32,
    ) -> Result<(), XtensaError> {
        // Store address and data
        interface
            .schedule_write_cpu_register(CpuRegister::A3, self.current_address)
            .await?;
        interface
            .schedule_write_cpu_register(CpuRegister::A4, data)
            .await?;

        // Increment address
        self.current_address += 4;

        // Store A4 into address A3
        interface
            .xdm
            .schedule_execute_instruction(Instruction::S32I(CpuRegister::A3, CpuRegister::A4, 0))
            .await;

        Ok(())
    }
}
