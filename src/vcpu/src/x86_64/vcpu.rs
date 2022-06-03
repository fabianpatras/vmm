use std::sync::Arc;

use crate::x86_64::exit_handler::{Error as ExitHandlerError, ExitHandler};
use crate::x86_64::gdt::{Gdt, SegmentDescriptor};
use crate::x86_64::vmx::*;
use crate::{rreg, rvmcs, wreg, wvmcs};
use crate::x86_64::cpuid::*;
use crate::x86_64::cpu_data::CpuData;

use hv::{
    x86::{
        vmx::{read_capability, Capability::*, VCpuVmxExt, Vmcs::*},
        Reg::*,
        VcpuExt,
    },
    Vcpu,
};
use std::mem;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory};

pub struct HvVcpu {
    vcpu: Vcpu,
    data: CpuData,
}

#[derive(Debug)]
pub enum Error {
    /// Error caused by `hv` while creating the vcpu
    HvCreateVcpu(hv::Error),
    /// Error caused by `hv` while running the vcpu
    HvRunVcpu(hv::Error),
    /// Error caused by `hv` while transitioning to protected mode
    ProtectedModeHv(hv::Error),
    /// Error caused by `vm_memory` while transitioning to protected mode
    ProtectedModeMemory(vm_memory::GuestMemoryError),
    /// Error caused by `vm_memory` while transitioning to protected mode
    ProtectedModeMemoryOffset,

    /// Exit caused by the handler of VM Exits
    ExitHandler(ExitHandlerError),
}

impl From<hv::Error> for Error {
    fn from(e: hv::Error) -> Self {
        return Self::ProtectedModeHv(e);
    }
}

impl HvVcpu {
    pub fn new<M: GuestMemory>(vm: Arc<hv::Vm>, guest_memory: &M) -> Result<HvVcpu, Error> {
        let vcpu = vm.create_cpu().map_err(Error::HvCreateVcpu)?;
        let hv_vcpu = HvVcpu { vcpu, data: Default::default() };

        hv_vcpu.set_up_protected_mode(guest_memory)?;

        Ok(hv_vcpu)
    }

    pub fn set_regs_for_boot(&self, rip: u64) -> Result<(), Error> {
        let vcpu = &self.vcpu;

        wvmcs!(vcpu, GUEST_RIP, rip);
        wvmcs!(vcpu, GUEST_RFLAGS, 0x0000_0000_0000_0002_u64);
        wvmcs!(vcpu, GUEST_RSP, BOOT_STACK_POINTER);
        wreg!(vcpu, RBP, BOOT_STACK_POINTER);
        wreg!(vcpu, RSI, ZEROPG_START);

        Ok(())
    }

    pub fn set_up_protected_mode<M: GuestMemory>(&self, guest_memory: &M) -> Result<(), Error> {
        let vcpu = &self.vcpu;

        Self::enable_native_msrs(vcpu)?;

        let mut cap: u64;
        cap = read_capability(ProcBased)?;
        wvmcs!(
            vcpu,
            CTRL_CPU_BASED,
            cap2ctrl(
                cap,
                CTRL_CPU_BASED_HLT | CTRL_CPU_BASED_CR8_LOAD | CTRL_CPU_BASED_CR8_STORE,
            )
        );

        cap = read_capability(ProcBased2)?;
        wvmcs!(vcpu, CTRL_CPU_BASED2, cap2ctrl(cap, 0));

        cap = read_capability(Entry)?;
        // wvmcs!(vcpu, CTRL_VMENTRY_CONTROLS, cap2ctrl(cap, 0));
        wvmcs!(
            vcpu,
            CTRL_VMENTRY_CONTROLS,
            cap2ctrl(
                cap,
                CTRL_VMENTRY_CONTROLS_IA32_MODE | CTRL_VMENTRY_CONTROLS_LOAD_IA32_EFER
            )
        );

        cap = read_capability(Exit)?;
        wvmcs!(vcpu, CTRL_VMEXIT_CONTROLS, cap2ctrl(cap, 0));

        // See Intel SMD3C 24.6.3 - setting a bit to 1 causes the exception to cauze a VM exit
        // See Intel SDM1 6.5.1 - Table 6-1 for exception details
        // wvmcs!(vcpu, CTRL_EXC_BITMAP, 0xffff_ffff);
        wvmcs!(vcpu, CTRL_EXC_BITMAP, 0x0);
        wvmcs!(vcpu, CTRL_CR0_MASK, 0x60000000);
        wvmcs!(vcpu, CTRL_CR0_SHADOW, 0x0);
        wvmcs!(vcpu, CTRL_CR4_MASK, X86_CR4_VMXE);
        wvmcs!(vcpu, CTRL_CR4_SHADOW, X86_CR4_VMXE);

        // Code segment
        wvmcs!(vcpu, GUEST_CS, 0x8);
        wvmcs!(vcpu, GUEST_CS_LIMIT, 0xffff);
        wvmcs!(vcpu, GUEST_CS_AR, 0xa09b);
        wvmcs!(vcpu, GUEST_CS_BASE, 0x0);

        // Data segment
        wvmcs!(vcpu, GUEST_DS, 0x10);
        wvmcs!(vcpu, GUEST_DS_LIMIT, 0xffff);
        wvmcs!(vcpu, GUEST_DS_AR, 0xc093);
        wvmcs!(vcpu, GUEST_DS_BASE, 0x0);

        // Stack segment
        wvmcs!(vcpu, GUEST_SS, 0x10);
        wvmcs!(vcpu, GUEST_SS_LIMIT, 0xffff);
        wvmcs!(vcpu, GUEST_SS_AR, 0xc093);
        wvmcs!(vcpu, GUEST_SS_BASE, 0x0);

        // Extra segment
        wvmcs!(vcpu, GUEST_ES, 0x10);
        wvmcs!(vcpu, GUEST_ES_LIMIT, 0xffff);
        wvmcs!(vcpu, GUEST_ES_AR, 0xc093);
        wvmcs!(vcpu, GUEST_ES_BASE, 0x0);

        // F segment
        wvmcs!(vcpu, GUEST_FS, 0x10);
        wvmcs!(vcpu, GUEST_FS_LIMIT, 0xffff);
        wvmcs!(vcpu, GUEST_FS_AR, 0xc093);
        wvmcs!(vcpu, GUEST_FS_BASE, 0x0);

        // G segment
        wvmcs!(vcpu, GUEST_GS, 0x10);
        wvmcs!(vcpu, GUEST_GS_LIMIT, 0xffff);
        wvmcs!(vcpu, GUEST_GS_AR, 0xc093);
        wvmcs!(vcpu, GUEST_GS_BASE, 0x0);

        // Task state segment
        wvmcs!(vcpu, GUEST_TR, 0x18);
        wvmcs!(vcpu, GUEST_TR_LIMIT, 0xffff);
        wvmcs!(vcpu, GUEST_TR_AR, 0x808b);
        wvmcs!(vcpu, GUEST_TR_BASE, 0x0);

        // Local Descriptor Table
        wvmcs!(vcpu, GUEST_LDTR, 0x0);
        // wvmcs!(vcpu, GUEST_LDTR_LIMIT, 0x0);
        wvmcs!(vcpu, GUEST_LDTR_LIMIT, 0xffff);
        wvmcs!(vcpu, GUEST_LDTR_AR, 0x8082);
        // wvmcs!(vcpu, GUEST_LDTR_AR, 0x10000); // (1<<16)
        wvmcs!(vcpu, GUEST_LDTR_BASE, 0x0);

        let null_seg = SegmentDescriptor::from(0, 0, 0);
        let code_seg = SegmentDescriptor::from(0xa09b, 0, 0xffff);
        let data_seg = SegmentDescriptor::from(0xc093, 0, 0xffff);
        let tss_seg = SegmentDescriptor::from(0x808b, 0, 0xffff);

        let gdt = Gdt(vec![null_seg, code_seg, data_seg, tss_seg]);

        for (idx, segment) in gdt.0.iter().enumerate() {
            let addr = guest_memory
                .checked_offset(
                    GuestAddress(BOOT_GDT_OFFSET),
                    idx * mem::size_of::<SegmentDescriptor>(),
                )
                .ok_or(Error::ProtectedModeMemoryOffset)?;
            guest_memory
                .write_obj(*segment, addr)
                .map_err(Error::ProtectedModeMemory)?;
        }

        // GDTR Global Description Table Register
        wvmcs!(vcpu, GUEST_GDTR_BASE, BOOT_GDT_OFFSET);
        wvmcs!(vcpu, GUEST_GDTR_LIMIT, 0x20);

        guest_memory
            .write_obj(0u64, GuestAddress(BOOT_IDT_OFFSET))
            .map_err(Error::ProtectedModeMemory)?;

        // IDTR Interrupt Description Table Register
        wvmcs!(vcpu, GUEST_IDTR_BASE, BOOT_IDT_OFFSET);
        wvmcs!(
            vcpu,
            GUEST_IDTR_LIMIT,
            (std::mem::size_of::<u64>() - 1) as u64
        );

        // CRx stuff
        let cr0 = X86_CR0_PE | X86_CR0_MP | X86_CR0_ET | X86_CR0_NE | X86_CR0_AM | X86_CR0_PG;
        wvmcs!(vcpu, GUEST_CR0, cr0);

        wvmcs!(vcpu, GUEST_CR3, 0x0);

        let cr4 = X86_CR4_VMXE | X86_CR4_PAE;
        wvmcs!(vcpu, GUEST_CR4, cr4);

        let mut efer = rvmcs!(vcpu, GUEST_IA32_EFER);
        efer |= X86_IA32_EFER_LME;
        // efer |= X86_IA32_EFER_LMA;
        wvmcs!(vcpu, GUEST_IA32_EFER, efer);

        wvmcs!(vcpu, CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
        wvmcs!(vcpu, GUEST_LINK_POINTER, !0x0);
        // See Intel SDM3B Figure 17-3
        // ia32_debugctl &= 0b00000000_00000000_11011111_11000011;
        // let mask = 0xDFC3;
        wvmcs!(vcpu, GUEST_IA32_DEBUGCTL, 0x0);
        // wvmcs!(vcpu, GUEST_LINK_POINTER, 0x1234123);

        Self::enter_long_mode(vcpu, efer)?;

        Ok(())
    }

    pub fn _set_up_real_mode(&self) -> Result<(), Error> {
        let vcpu = &self.vcpu;

        let mut cap: u64;

        cap = read_capability(ProcBased).unwrap();

        wvmcs!(
            vcpu,
            CTRL_CPU_BASED,
            cap2ctrl(
                cap,
                CTRL_CPU_BASED_HLT | CTRL_CPU_BASED_CR8_LOAD | CTRL_CPU_BASED_CR8_STORE,
            )
        );

        cap = read_capability(ProcBased2).unwrap();
        wvmcs!(vcpu, CTRL_CPU_BASED2, cap2ctrl(cap, 0));

        cap = read_capability(Entry).unwrap();
        wvmcs!(vcpu, CTRL_VMENTRY_CONTROLS, cap2ctrl(cap, 0));

        cap = read_capability(Exit).unwrap();
        wvmcs!(vcpu, CTRL_VMEXIT_CONTROLS, cap2ctrl(cap, 0));

        wvmcs!(vcpu, CTRL_EXC_BITMAP, 0x0);
        wvmcs!(vcpu, CTRL_CR0_MASK, 0x60000000);
        wvmcs!(vcpu, CTRL_CR0_SHADOW, 0x0);
        wvmcs!(vcpu, CTRL_CR4_MASK, 0x0);
        wvmcs!(vcpu, CTRL_CR4_SHADOW, 0x0);

        // Code segment
        wvmcs!(vcpu, GUEST_CS, 0x0);
        wvmcs!(vcpu, GUEST_CS_LIMIT, 0xffff);
        wvmcs!(vcpu, GUEST_CS_AR, 0x9b);
        wvmcs!(vcpu, GUEST_CS_BASE, 0x0);

        // Data segment
        wvmcs!(vcpu, GUEST_DS, 0x0);
        wvmcs!(vcpu, GUEST_DS_LIMIT, 0xffff);
        wvmcs!(vcpu, GUEST_DS_AR, 0x93);
        wvmcs!(vcpu, GUEST_DS_BASE, 0x0);

        // Stack segment
        wvmcs!(vcpu, GUEST_SS, 0x0);
        wvmcs!(vcpu, GUEST_SS_LIMIT, 0xffff);
        wvmcs!(vcpu, GUEST_SS_AR, 0x93);
        wvmcs!(vcpu, GUEST_SS_BASE, 0x0);

        // Extra segment
        wvmcs!(vcpu, GUEST_ES, 0x0);
        wvmcs!(vcpu, GUEST_ES_LIMIT, 0xffff);
        wvmcs!(vcpu, GUEST_ES_AR, 0x93);
        wvmcs!(vcpu, GUEST_ES_BASE, 0x0);

        // F segment
        wvmcs!(vcpu, GUEST_FS, 0x0);
        wvmcs!(vcpu, GUEST_FS_LIMIT, 0xffff);
        wvmcs!(vcpu, GUEST_FS_AR, 0x93);
        wvmcs!(vcpu, GUEST_FS_BASE, 0x0);

        // G segment
        wvmcs!(vcpu, GUEST_GS, 0x0);
        wvmcs!(vcpu, GUEST_GS_LIMIT, 0xffff);
        wvmcs!(vcpu, GUEST_GS_AR, 0x93);
        wvmcs!(vcpu, GUEST_GS_BASE, 0x0);

        // Task state segment
        wvmcs!(vcpu, GUEST_TR, 0x0);
        wvmcs!(vcpu, GUEST_TR_LIMIT, 0xffff);
        wvmcs!(vcpu, GUEST_TR_AR, 0x83);
        wvmcs!(vcpu, GUEST_TR_BASE, 0x0);

        // Local Descriptor Table
        wvmcs!(vcpu, GUEST_LDTR, 0x0);
        wvmcs!(vcpu, GUEST_LDTR_LIMIT, 0x0);
        wvmcs!(vcpu, GUEST_LDTR_AR, 0x10000); // (1<<16)
        wvmcs!(vcpu, GUEST_LDTR_BASE, 0x0);

        // GDTR Global Description Table Register
        wvmcs!(vcpu, GUEST_GDTR_LIMIT, 0x0);
        wvmcs!(vcpu, GUEST_GDTR_BASE, 0x0);

        // IDTR Interrupt Description Table Register
        wvmcs!(vcpu, GUEST_IDTR_LIMIT, 0x0);
        wvmcs!(vcpu, GUEST_IDTR_BASE, 0x0);

        // CR stuff
        wvmcs!(vcpu, GUEST_CR0, 0x20);
        wvmcs!(vcpu, GUEST_CR3, 0x0);
        wvmcs!(vcpu, GUEST_CR4, 0x2000); // CR4.VMXE = (1 << 13)

        Ok(())
    }

    pub fn run(&self) -> Result<(), Error> {
        let vcpu = &self.vcpu;
        let mut exits: u64 = 0;

        println!("Running vcpu...");
        loop {
            vcpu.run_until(VCPU_DEADLINE_FOREVER)
                .map_err(Error::HvRunVcpu)?;

            let exit_reason = rvmcs!(vcpu, RO_EXIT_REASON);
            let exit_qualific = rvmcs!(vcpu, RO_EXIT_QUALIFIC);
            exits += 1;

            match exit_reason {
                ER_EXC_NMI => {
                    println!(
                        "Got Exeption Exit reason IRQ info [{:#X}][{:#b}]",
                        rvmcs!(vcpu, RO_VMEXIT_IRQ_INFO),
                        rvmcs!(vcpu, RO_VMEXIT_IRQ_INFO)
                    );
                    break;
                }
                ER_TRIPLE_FAULT => {
                    println!("got triple fault!");
                    self.dump_vcpu_state()?;
                    break;
                }
                ER_CPUID => {
                    println!(
                        "EAX:ECX = [{:#X}:{:#X}]",
                        rreg!(vcpu, RAX),
                        rreg!(vcpu, RCX)
                    );
                    self.handle_cpuid().map_err(Error::ExitHandler)?;
                    self.advance_rip()?;
                }
                ER_HLT => {
                    println!("Got HLT Exit reason");
                    break;
                }
                ER_MOV_CR => {
                    println!("mov to cr");
                    println!("exit qual [{:#X}][{:#b}]", exit_qualific, exit_qualific);
                    self.handle_mov_cr().map_err(Error::ExitHandler)?;
                    self.advance_rip()?;
                }
                ER_RDMSR => {
                    self.handle_msr_access(true).map_err(Error::ExitHandler)?;
                    self.advance_rip()?;
                }
                ER_WRMSR => {
                    self.handle_msr_access(false).map_err(Error::ExitHandler)?;
                    self.advance_rip()?;
                }
                er if (er & VM_EXIT_VM_ENTRY_FAILURE) != 0 => {
                    println!(
                        "Got VMENTRY FALURE error [{:#X}] with qualific [{:#X}]. Aborting...",
                        er & !VM_EXIT_VM_ENTRY_FAILURE,
                        exit_qualific
                    );
                    break;
                }
                ER_EPT_VIOLATION => {
                    println!(
                        "Got EPT Violation with qual [{:#X}]. Skipping...",
                        exit_qualific
                    );
                }
                er => {
                    println!(
                        "Got unknown exit reason [{:#X}] with qualific [{:#X}]. Exiting...",
                        er, exit_qualific
                    );
                    break;
                }
            }
        }

        println!("Exited after [{}] VM Exits!", exits);

        Ok(())
    }

    pub fn print_exit_instruction<M: GuestMemory>(&self, guest_memory: &M) -> Result<(), Error> {
        let vcpu = &self.vcpu;
        let rip = rvmcs!(vcpu, GUEST_PHYSICAL_ADDRESS);
        let instr_len = rvmcs!(vcpu, RO_VMEXIT_INSTR_LEN);
        let mut container: [u8; 16] = [0; 16];

        guest_memory
            .read(&mut container, GuestAddress(rip))
            .unwrap();

        for i in 0..16 {
            print!("{:#x} ", container[i as usize]);
        }
        println!("");

        Ok(())
    }

    pub fn dump_vcpu_state(&self) -> Result<(), Error> {
        dump_vmcs(&self.vcpu)?;

        Ok(())
    }

    /// sets up 512 2MB pages of physical space for VA space [0x0, 0x4000_0000)
    pub fn paging_mode_setup_4_level<M: GuestMemory>(&self, guest_memory: &M) -> Result<(), Error> {
        let vcpu = &self.vcpu;

        // See Intel SDM3A 4.5 4-LEVEL PAGING
        // With ordinary paging, CR3 locates the first paging structure, PML4
        // The PML4 contains 2^9 PML4E, each one referencing a PDPT (see PAE)
        // We're going to use 2MB pages, See Intel SMD3A Figure 4-9

        // this is the 8-th physical page
        let pml4_pa = 8 * PAGE_SIZE_32_BIT;

        // this is the 9-th physical page
        let pdpt_pa = 9 * PAGE_SIZE_32_BIT;

        // this is the 10-th physical page
        let page_directory_pa = 10 * PAGE_SIZE_32_BIT;

        let pml4_address = GuestAddress(pml4_pa as u64);
        let pdpt_address = GuestAddress(pdpt_pa as u64);
        let page_directory_address = GuestAddress(page_directory_pa as u64);

        wvmcs!(vcpu, GUEST_CR3, pml4_address.raw_value());

        // See Intel SDM3A 4.5 Table 4-15
        // writing a single PLM4 Entry (Page-Directory-Pointer-Table)
        // with Present bit and Write Bit into PML4 Table
        // this refers a region of 512GB
        guest_memory
            .write_obj(
                pdpt_address.raw_value() | X86_PLM4E_P | X86_PLM4E_RW | X86_PLM4E_U,
                pml4_address,
            )
            .unwrap();

        // See Intel SDM3A 4.5.4 Table 4-17
        // writing a single PDPT Entry (Page Directory)
        // with Present bit and Write Bit into PDP Table
        // this refers to a region of 1GB
        guest_memory
            .write_obj(
                page_directory_address.raw_value() | X86_PDPTE_P | X86_PDPTE_RW | X86_PDPTE_U,
                pdpt_address,
            )
            .unwrap();

        // See Intel SDM3A 4.5.4 Table 4-18
        // writing 512 PDE (2MB Page each)
        // with Present bit and Write Bit into Page Directory
        // this refers to a region of 1GB
        for i in 0..512 {
            guest_memory
                .write_obj(
                    (i << 21) | X86_PDE_P | X86_PDE_RW | X86_PDE_U | X86_PDE_PS,
                    // this will always be ok because there is enought room in a 4KB Page Directory structure
                    // for 512 64-bit entries
                    page_directory_address.unchecked_add(8 * i),
                )
                .unwrap();
        }

        Ok(())
    }

    fn advance_rip(&self) -> Result<(), Error> {
        let vcpu = &self.vcpu;
        let rip = rreg!(vcpu, RIP);
        let instr_len = rvmcs!(vcpu, RO_VMEXIT_INSTR_LEN);
        println!("\t> Advancind RIP from [{:#X}] to [{:#X}]", rip, rip + instr_len);

        wreg!(vcpu, RIP, rip + instr_len);

        Ok(())
    }

    // adapted from qemu
    fn enter_long_mode(vcpu: &Vcpu, mut efer: u64) -> Result<(), hv::Error> {
        let ar_type_mask = 0x0f;
        let ar_type_busy_tss = 0x0b;

        efer |= X86_IA32_EFER_LMA;
        wvmcs!(vcpu, GUEST_IA32_EFER, efer);

        let entry_ctls = rvmcs!(vcpu, CTRL_VMENTRY_CONTROLS);
        wvmcs!(
            vcpu,
            CTRL_VMENTRY_CONTROLS,
            entry_ctls | CTRL_VMENTRY_CONTROLS_IA32_MODE
        );

        if efer & X86_IA32_EFER_LME != 0 {
            let tr_ar = rvmcs!(vcpu, GUEST_TR_AR);
            if tr_ar & ar_type_mask != ar_type_busy_tss {
                wvmcs!(
                    vcpu,
                    GUEST_TR_AR,
                    (tr_ar & !ar_type_mask) | ar_type_busy_tss
                );
            }
        }

        Ok(())
    }

    fn enable_native_msrs(vcpu: &Vcpu) -> Result<(), hv::Error> {
        vcpu.enable_native_msr(MSR_IA32_SYSENTER_CS, true)?;
        vcpu.enable_native_msr(MSR_IA32_SYSENTER_EIP, true)?;
        vcpu.enable_native_msr(MSR_IA32_SYSENTER_ESP, true)?;

        vcpu.enable_native_msr(MSR_IA32_STAR, true)?;
        vcpu.enable_native_msr(MSR_IA32_CSTAR, true)?;
        vcpu.enable_native_msr(MSR_IA32_LSTAR, true)?;

        vcpu.enable_native_msr(MSR_IA32_TSC, true)?;

        // this MSR is the only mandatory one so far (not enabling causes a `hv` framework error on run)
        vcpu.enable_native_msr(MSR_IA32_KERNEL_GS_BASE, true)?;

        vcpu.enable_native_msr(MSR_IA32_FS_BASE, true)?;
        vcpu.enable_native_msr(MSR_IA32_GS_BASE, true)?;
        vcpu.enable_native_msr(MSR_IA32_TSC_AUX, true)?;

        Ok(())
    }
}

impl ExitHandler for HvVcpu {
    type E = ExitHandlerError;

    fn handle_cpuid(&self) -> Result<(), Self::E> {
        let vcpu = &self.vcpu;
        let eax = rreg!(vcpu, RAX) as u32;
        let ecx = rreg!(vcpu, RCX) as u32;

        // firstly use host inbuild cpuid then decide if we have to mask
        // reject or pass in clear
        let cpuidres = cpuid_count(eax, ecx);
        
        wreg!(vcpu, RAX, cpuidres.eax as u64);
        wreg!(vcpu, RBX, cpuidres.ebx as u64);
        wreg!(vcpu, RCX, cpuidres.ecx as u64);
        wreg!(vcpu, RDX, cpuidres.edx as u64);

        // 1) supported and we have to mask something -> early return
        // 2) supported and we pass directly to host inbuild cpuid
        // 3) not supported -> exit with Err
        match eax {
            0x0 => {
                // 1) supported
            },
            0x1 => {
                // 1) supported
            },
            0x6 => {
                // 2) supported, modified
                wreg!(vcpu, RAX, CPUID_6_EAX);
                wreg!(vcpu, RBX, 0x0);
                wreg!(vcpu, RCX, 0x0);
                wreg!(vcpu, RDX, 0x0);
            },
            0x7 => {
                // 2) supported, modidfied
                // disable SGX support
                wreg!(vcpu, RBX, rreg!(vcpu, RBX) & !CPUID_7_0_EBX_SGX_MASK);
                wreg!(vcpu, RCX, rreg!(vcpu, RCX) & !CPUID_7_0_ECX_SGX_LC_MASK);
            },
            0xB => {
                // 1) supported
            },
            0xD => {
                // 1) supported
            },
            0xF => {
                // 1) supported
            },
            0x10 => {
                // 1) supported
            },
            0x80000000 => {
                // 1) supported
            },
            0x80000001 => {
                // 1) supported
            },
            0x80000007 => {
                // 1) supported
            },
            0x80000008 => {
                // 1) supported
            },

            _ => {
                return Err(ExitHandlerError::CpuIdLeafNotSupported(eax, ecx));
            }
        }

        Ok(())
    }

    fn handle_mov_cr(&self) -> Result<(), Self::E> {
        let vcpu = &self.vcpu;

        let exit_qual = rvmcs!(vcpu, RO_EXIT_QUALIFIC);
        let reg = exit_qual & 0x0f;
        let instr = (exit_qual >> 4) & 0x03;
        let source = (exit_qual >> 8) & 0x0f;

        // CR4
        if reg != 4 {
            return Err(ExitHandlerError::CrAccessRegisterNotSupported);
        }

        if instr != 0 {
            return Err(ExitHandlerError::CrAccessAccessTypeNotSupported);
        }

        wreg!(
            vcpu,
            CR4,
            rreg!(vcpu, REGS[source as usize]) | rvmcs!(vcpu, CTRL_CR4_SHADOW)
        );

        Ok(())
    }

    fn handle_msr_access(&self, read: bool) -> Result<(), Self::E> {
        let vcpu = &self.vcpu;
        let msr_index = rreg!(vcpu, RCX) as u32;
        let mut val: u64 = (rreg!(vcpu, RDX) << 32) | (rreg!(vcpu, RAX) & 0xFFFF_FFFF);

        println!(
            "MSR Access Read[{}] index[{:#X}] [{:#X}]",
            read, msr_index, val
        );

        if read {
            match msr_index {
                MSR_IA32_EFER => {
                    val = rvmcs!(vcpu, GUEST_IA32_EFER);
                },
                MSR_IA32_MISC_ENABLE => {
                    val = self.data.msr_ia32_misc_enable;
                },
                MSR_IA32_BIOS_SIGN_ID => {
                    val = 0;
                    // nothing?
                },
                MSR_IA32_ARCH_CAPABILITIES => {
                    val = 0;
                    // nothing?
                },

                _ => {
                    return Err(ExitHandlerError::MsrIndexNotSupportedRead(msr_index));
                }
            }

            wreg!(vcpu, RAX, val);
            wreg!(vcpu, RDX, val >> 32);
        } else {
            match msr_index {
                MSR_IA32_EFER => {
                    wvmcs!(
                        vcpu,
                        GUEST_IA32_EFER,
                        (val | (X86_IA32_EFER_LMA | X86_IA32_EFER_LME)) & !(1)
                    );
                },

                MSR_IA32_GS_BASE => {
                    wvmcs!(vcpu, GUEST_GS_BASE, val);
                },
                MSR_IA32_BIOS_SIGN_ID => {
                    // wvmcs!(vcpu, GUEST_GS_BASE, val);
                    // nothing?
                },

                _ => return Err(ExitHandlerError::MsrIndexNotSupportedWrite(msr_index)),
            }
        }

        Ok(())
    }
}
