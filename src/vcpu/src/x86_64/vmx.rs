use hv::{
    x86::{
        vmx::{read_capability, Capability::*, Reason::*, VCpuVmxExt, Vmcs::*},
        Reg,
        Reg::*,
        VcpuExt,
    },
    Vcpu,
};

/// The offset at which GDT resides in memory.
pub const BOOT_GDT_OFFSET: u64 = 0x500;
/// The offset at which IDT resides in memory.
pub const BOOT_IDT_OFFSET: u64 = 0x520;
/// Maximum number of GDT entries as defined in the Intel Specification.
pub const MAX_GDT_SIZE: usize = 1 << 13;
/// Address of the zeropage, where Linux kernel boot parameters are written.
pub const ZEROPG_START: u64 = 0x7000;
/// Address where the kernel command line is written.
pub const CMDLINE_START: u64 = 0x0002_0000;
/// Initial stack for the boot CPU.
pub const BOOT_STACK_POINTER: u64 = 0x8ff0;
/// Default highmem start
pub const HIGHMEM_START_ADDRESS: u64 = 0x10_0000;
/// Default kernel command line.
pub const DEFAULT_KERNEL_CMDLINE: &str = "panic=1 pci=off";

// x86_64 boot pub constants. See https://www.kernel.org/doc/Documentation/x86/boot.txt for the full
// documentation.
// Header field: `boot_flag`. Must contain 0xaa55.
pub const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
// Header field: `header`. Must contain the magic number `HdrS` (0x5372_6448).
pub const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
// Header field: `type_of_loader`.
pub const KERNEL_LOADER_OTHER: u8 = 0xff;
// Header field: `kernel_alignment`. Alignment unit required by a relocatable kernel.
pub const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000;

// Start address for the EBDA (Extended Bios Data Area).
// See https://wiki.osdev.org/Memory_Map_(x86) for more information.
pub const EBDA_START: u64 = 0x0009_fc00;
// RAM memory type.
pub const E820_RAM: u32 = 1;

/// First address past 32 bits is where the MMIO gap ends.
pub const MMIO_GAP_END: u64 = 1 << 32;
/// Size of the MMIO gap.
pub const MMIO_GAP_SIZE: u64 = 768 << 20;
/// The start of the MMIO gap (memory area reserved for MMIO devices).
pub const MMIO_GAP_START: u64 = MMIO_GAP_END - MMIO_GAP_SIZE;

// page map level 4 start offset
pub const PML4_START: u64 = 0x9000;
//  page-directory-pointer table entry start offset
pub const PDPTE_START: u64 = 0xA000;
//  page-directory entry start offset
pub const PDE_START: u64 = 0xB000;

// See Intel SDM3A 2.5
pub const X86_CR0_PE: u64 = 1 << 0;
pub const X86_CR0_MP: u64 = 1 << 1;
pub const X86_CR0_ET: u64 = 1 << 4;
pub const X86_CR0_NE: u64 = 1 << 5;
pub const X86_CR0_WP: u64 = 1 << 16;
pub const X86_CR0_AM: u64 = 1 << 18;
pub const X86_CR0_PG: u64 = 1 << 31;

// See Intel SDM3A 2.5
pub const X86_CR4_PAE: u64 = 1 << 5;
pub const X86_CR4_VMXE: u64 = 1 << 13;

// See Intel SDM3A 2.2.1 Table 2-1
pub const X86_IA32_EFER_LME: u64 = 1 << 8;
pub const X86_IA32_EFER_LMA: u64 = 1 << 10;

// See Intel SDM3A 4.5.4 Table 4-15
pub const X86_PLM4E_P: u64 = 1 << 0;
pub const X86_PLM4E_RW: u64 = 1 << 1;
pub const X86_PLM4E_U: u64 = 1 << 2;

// See Intel SDM3A 4.5.4 Table 4-17
pub const X86_PDPTE_P: u64 = 1 << 0;
pub const X86_PDPTE_RW: u64 = 1 << 1;
pub const X86_PDPTE_U: u64 = 1 << 2;

// See Intel SDM3A 4.3 Table 4-5 (for 32-bit paging mode)
// See Intel SDM3A 4.5.4 Table 4-18
pub const X86_PDE_P: u64 = 1 << 0;
pub const X86_PDE_RW: u64 = 1 << 1;
pub const X86_PDE_U: u64 = 1 << 2;
pub const X86_PDE_PS: u64 = 1 << 7;

// See Intel SDM3A 4.4.1 Table 4-8
pub const X86_PAE_PDPTE_P: u64 = 1 << 0;

// See Intel SDM3C 24.6.2
pub const CTRL_CPU_BASED_HLT: u64 = 1 << 7;
pub const CTRL_CPU_BASED_CR8_LOAD: u64 = 1 << 19;
pub const CTRL_CPU_BASED_CR8_STORE: u64 = 1 << 20;

// See Intel SDM3C 24.8.1
pub const CTRL_VMENTRY_CONTROLS_IA32_MODE: u64 = 1 << 9;
pub const CTRL_VMENTRY_CONTROLS_LOAD_IA32_EFER: u64 = 1 << 15;

pub const VM_EXIT_VM_ENTRY_FAILURE: u64 = 1 << 31;

// See Intel SDM4 Table 2-2
pub const IA32_VMX_CR0_FIXED0: u32 = 0x486;
pub const IA32_VMX_CR0_FIXED1: u32 = 0x487;
pub const IA32_VMX_CR4_FIXED0: u32 = 0x488;
pub const IA32_VMX_CR4_FIXED1: u32 = 0x489;

// https://developer.apple.com/documentation/hypervisor/3727856-model-specific_registers?language=objc
pub const HV_MSR_IA32_SYSENTER_EIP: u32 = 0x00000176;

// default page size
pub const PAGE_SIZE_32_BIT: u32 = 4096; //bytes

// See Intel SDM4 Table 2-2 MSR indexes
pub const MSR_IA32_TSC: u32 = 0x00000010;
pub const MSR_IA32_SYSENTER_CS: u32 = 0x00000174;
pub const MSR_IA32_SYSENTER_ESP: u32 = 0x00000175;
pub const MSR_IA32_SYSENTER_EIP: u32 = 0x00000176;
pub const MSR_IA32_EFER: u32 = 0xc0000080;
pub const MSR_IA32_STAR: u32 = 0xc0000081;
pub const MSR_IA32_LSTAR: u32 = 0xc0000082;
pub const MSR_IA32_CSTAR: u32 = 0xc0000083;
pub const MSR_IA32_SYSCALL_MASK: u32 = 0xc0000084;
pub const MSR_IA32_FS_BASE: u32 = 0xc0000100;
pub const MSR_IA32_GS_BASE: u32 = 0xc0000101;
pub const MSR_IA32_KERNEL_GS_BASE: u32 = 0xc0000102;
pub const MSR_IA32_TSC_AUX: u32 = 0xc0000103;

pub const VCPU_DEADLINE_FOREVER: u64 = 0xFFFF_FFFF_FFFF_FFFF;

// exit reasons as u64
pub const ER_EXC_NMI: u64 = EXC_NMI as u64;
pub const ER_TRIPLE_FAULT: u64 = TRIPLE_FAULT as u64;
pub const ER_CPUID: u64 = CPUID as u64;
pub const ER_HLT: u64 = HLT as u64;
pub const ER_MOV_CR: u64 = MOV_CR as u64;
pub const ER_RDMSR: u64 = RDMSR as u64;
pub const ER_WRMSR: u64 = WRMSR as u64;
pub const ER_VMENTRY_GUEST: u64 = VMENTRY_GUEST as u64;
pub const ER_EPT_VIOLATION: u64 = EPT_VIOLATION as u64;

pub const CPUID_LZCNT: u64 = 1 << 5;

pub const REGS: [Reg; 16] = [
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15,
];

// Read register
#[macro_export]
macro_rules! rreg {
    ($vcpu:expr, $register_field:expr) => {{
        $vcpu.read_register($register_field)?
    }};
}

// Write register
#[macro_export]
macro_rules! wreg {
    ($vcpu:expr, $register_field:expr, $value:expr) => {{
        $vcpu.write_register($register_field, $value)?;
    }};
}

// Read vmcs field
#[macro_export]
macro_rules! rvmcs {
    ($vcpu:expr, $vmcs_field:expr) => {{
        $vcpu.read_vmcs($vmcs_field)?
    }};
}

// Write vmcs field
#[macro_export]
macro_rules! wvmcs {
    ($vcpu:expr, $vmcs_field:expr, $value:expr) => {{
        $vcpu.write_vmcs($vmcs_field, $value)?;
    }};
}

// Read MSR
#[macro_export]
macro_rules! rmsr {
    ($vcpu:expr, $msr_index:expr) => {{
        $vcpu.read_msr($msr_index)?
    }};
}

// Prints the value in both hex and binary with text as label
#[macro_export]
macro_rules! color_print {
    ($text:expr, $value:expr) => {{
        println!(
            "\t[\x1b[92m{}\x1b[0m][Hex: \x1b[96m{:#X}\x1b[0m][Bin: \x1b[95m{:#b}\x1b[0m]",
            $text, $value, $value
        );
    }};
}

// prints vmcs field
#[macro_export]
macro_rules! print_vmcs {
    ($vcpu:expr, $name:expr ,$vmcs_field:expr) => {{
        // let res: u64 = $vcpu.read_vmcs($vmcs_field)?;
        color_print!($name, rvmcs!($vcpu, $vmcs_field));
        // res
    }};
}

// prints register
#[macro_export]
macro_rules! print_register {
    ($vcpu:expr, $name:expr ,$register_field:expr) => {{
        // let res: u64 = $vcpu.read_register($register_field)?;
        color_print!($name, rreg!($vcpu, $register_field));
        // res
    }};
}

#[macro_export]
macro_rules! print_msr {
    ($s:expr, $name:expr ,$msr_index:expr) => {{
        color_print!($name, rmsr!($s.vcpu, $msr_index));
    }};
}

pub fn cap2ctrl(cap: u64, mut ctrl: u64) -> u64 {
    let allowed_0: u64 = cap & 0x0000_0000_FFFF_FFFFu64;
    let allowed_1: u64 = cap >> 32;

    ctrl &= 0x0000_0000_FFFF_FFFFu64;

    (ctrl | allowed_0) & allowed_1
}

pub fn dump_vmcs(vcpu: &Vcpu) -> Result<(), hv::Error> {
    println!("~~~~~ VMCS Dump ~~~~~");
    println!("~~~~ Capabilities ~~~");

    let mut cap: u64 = read_capability(PinBased)?;
    color_print!("PIN BASED CAP", cap);

    cap = read_capability(ProcBased)?;
    color_print!("PROC BASED CAP", cap);

    cap = read_capability(ProcBased2)?;
    color_print!("PROC BASED2 CAP", cap);

    cap = read_capability(Exit)?;
    color_print!("EXIT CAP", cap);

    cap = read_capability(Entry)?;
    color_print!("ENTRY CAP", cap);

    cap = read_capability(PreemptionTimer)?;
    color_print!("TIMER CAP", cap);

    println!("");
    println!("~~~~ VMX control ~~~~");
    print_vmcs!(vcpu, "PIN_BASED_CONTROLS", CTRL_PIN_BASED);
    print_vmcs!(vcpu, "CPU_BASED_CONTROLS", CTRL_CPU_BASED);
    print_vmcs!(vcpu, "CPU_BASED2_CONTROLS", CTRL_CPU_BASED2);
    print_vmcs!(vcpu, "VMEXIT_CONTROLS", CTRL_VMEXIT_CONTROLS);
    print_vmcs!(vcpu, "VMENTRY_CONTROLS", CTRL_VMENTRY_CONTROLS);
    print_vmcs!(vcpu, "VMENTRY_IRQ_INFO", CTRL_VMENTRY_IRQ_INFO);
    print_vmcs!(vcpu, "EXECUTION_BITMAP", CTRL_EXC_BITMAP);
    print_vmcs!(vcpu, "EPTP", CTRL_EPTP);
    print_vmcs!(vcpu, "VMENTRY_MSR_LOAD_COUNT", CTRL_VMENTRY_MSR_LOAD_COUNT);
    print_vmcs!(vcpu, "VMENTRY_MSR_LOAD_ADDR", CTRL_VMENTRY_MSR_LOAD_ADDR);

    println!("");
    println!("~~~~ Exit reason ~~~~");
    print_vmcs!(vcpu, "EXIT_REASON", RO_EXIT_REASON);
    print_vmcs!(vcpu, "EXIT_QUALIFIC", RO_EXIT_QUALIFIC);
    print_vmcs!(vcpu, "VMEXIT_INSTR_LEN", RO_VMEXIT_INSTR_LEN);
    print_vmcs!(vcpu, "GUEST_LIN_ADDR", RO_GUEST_LIN_ADDR);
    print_vmcs!(vcpu, "GUEST_PHYSICAL_ADDRESS", GUEST_PHYSICAL_ADDRESS);

    println!("");
    println!("~~~~ Guest State ~~~~");
    print_vmcs!(vcpu, "CR0", GUEST_CR0);
    print_vmcs!(vcpu, "CR3", GUEST_CR3);
    print_vmcs!(vcpu, "CR3_COUNT", CTRL_CR3_COUNT);
    print_vmcs!(vcpu, "CR3_TARGET0", CTRL_CR3_VALUE0);
    print_vmcs!(vcpu, "CR3_TARGET1", CTRL_CR3_VALUE1);
    print_vmcs!(vcpu, "CR3_TARGET2", CTRL_CR3_VALUE2);
    print_vmcs!(vcpu, "CR3_TARGET3", CTRL_CR3_VALUE3);
    print_vmcs!(vcpu, "CR4", GUEST_CR4);
    print_vmcs!(vcpu, "DR7", GUEST_DR7);

    println!("");
    print_vmcs!(vcpu, "CR0_MASK", CTRL_CR0_MASK);
    print_vmcs!(vcpu, "CR0_SHADOW", CTRL_CR0_SHADOW);
    print_vmcs!(vcpu, "CR4_MASK", CTRL_CR4_MASK);
    print_vmcs!(vcpu, "CR4_SHADOW", CTRL_CR4_SHADOW);

    // println!("");
    // print_msr!(vcpu, "IA32_VMX_CR0_FIXED0", IA32_VMX_CR0_FIXED0);
    // print_msr!(vcpu, "IA32_VMX_CR0_FIXED1", IA32_VMX_CR0_FIXED1);
    // print_msr!(vcpu, "IA32_VMX_CR4_FIXED0", IA32_VMX_CR4_FIXED0);
    // print_msr!(vcpu, "IA32_VMX_CR4_FIXED1", IA32_VMX_CR4_FIXED1);

    println!("");
    print_vmcs!(vcpu, "CS_SELECTOR", GUEST_CS);
    print_vmcs!(vcpu, "CS_BASE", GUEST_CS_BASE);
    print_vmcs!(vcpu, "CS_LIMIT", GUEST_CS_LIMIT);
    print_vmcs!(vcpu, "CS_AR", GUEST_CS_AR);

    println!("");
    print_vmcs!(vcpu, "DS_SELECTOR", GUEST_DS);
    print_vmcs!(vcpu, "DS_BASE", GUEST_DS_BASE);
    print_vmcs!(vcpu, "DS_LIMIT", GUEST_DS_LIMIT);
    print_vmcs!(vcpu, "DS_AR", GUEST_DS_AR);

    println!("");
    print_vmcs!(vcpu, "ES_SELECTOR", GUEST_ES);
    print_vmcs!(vcpu, "ES_BASE", GUEST_ES_BASE);
    print_vmcs!(vcpu, "ES_LIMIT", GUEST_ES_LIMIT);
    print_vmcs!(vcpu, "ES_AR", GUEST_ES_AR);

    println!("");
    print_vmcs!(vcpu, "FS_SELECTOR", GUEST_FS);
    print_vmcs!(vcpu, "FS_BASE", GUEST_FS_BASE);
    print_vmcs!(vcpu, "FS_LIMIT", GUEST_FS_LIMIT);
    print_vmcs!(vcpu, "FS_AR", GUEST_FS_AR);

    println!("");
    print_vmcs!(vcpu, "GS_SELECTOR", GUEST_GS);
    print_vmcs!(vcpu, "GS_BASE", GUEST_GS_BASE);
    print_vmcs!(vcpu, "GS_LIMIT", GUEST_GS_LIMIT);
    print_vmcs!(vcpu, "GS_AR", GUEST_GS_AR);

    println!("");
    print_vmcs!(vcpu, "SS_SELECTOR", GUEST_SS);
    print_vmcs!(vcpu, "SS_BASE", GUEST_SS_BASE);
    print_vmcs!(vcpu, "SS_LIMIT", GUEST_SS_LIMIT);
    print_vmcs!(vcpu, "SS_AR", GUEST_SS_AR);

    println!("");
    print_vmcs!(vcpu, "TR_SELECTOR", GUEST_TR);
    print_vmcs!(vcpu, "TR_BASE", GUEST_TR_BASE);
    print_vmcs!(vcpu, "TR_LIMIT", GUEST_TR_LIMIT);
    print_vmcs!(vcpu, "TR_AR", GUEST_TR_AR);

    println!("");
    print_vmcs!(vcpu, "GDTR_BASE", GUEST_GDTR_BASE);
    print_vmcs!(vcpu, "GDTR_LIMIT", GUEST_GDTR_LIMIT);

    println!("");
    print_vmcs!(vcpu, "IDTR_BASE", GUEST_IDTR_BASE);
    print_vmcs!(vcpu, "IDTR_LIMIT", GUEST_IDTR_LIMIT);

    println!("");
    print_vmcs!(vcpu, "LDTR_BASE", GUEST_LDTR_BASE);
    print_vmcs!(vcpu, "LDTR_LIMIT", GUEST_LDTR_LIMIT);
    print_vmcs!(vcpu, "LDTR_AR", GUEST_LDTR_AR);

    println!("");
    print_vmcs!(vcpu, "RIP", GUEST_RIP);
    print_vmcs!(vcpu, "RSP", GUEST_RSP);
    print_vmcs!(vcpu, "RFLAGS", GUEST_RFLAGS);

    println!("");
    print_vmcs!(vcpu, "SYSENTER_EIP", GUEST_SYSENTER_EIP);
    print_vmcs!(vcpu, "SYSENTER_ESP", GUEST_SYSENTER_ESP);
    print_vmcs!(vcpu, "SYSENTER_CS", GUEST_IA32_SYSENTER_CS);

    println!("");
    print_vmcs!(vcpu, "IA32_EFER", GUEST_IA32_EFER);
    print_vmcs!(vcpu, "IA32_DEBUGCTL", GUEST_IA32_DEBUGCTL);
    print_vmcs!(vcpu, "IA32_PAT", GUEST_IA32_PAT);
    print_vmcs!(vcpu, "ACTIVITY_STATE", GUEST_ACTIVITY_STATE);
    print_vmcs!(vcpu, "LINK_POINTER", GUEST_LINK_POINTER);

    println!("");
    print_vmcs!(vcpu, "PDPTE0", GUEST_PDPTE0);
    print_vmcs!(vcpu, "PDPTE1", GUEST_PDPTE1);
    print_vmcs!(vcpu, "PDPTE2", GUEST_PDPTE2);
    print_vmcs!(vcpu, "PDPTE3", GUEST_PDPTE3);

    println!("");
    print_register!(vcpu, "RIP", RIP);
    print_register!(vcpu, "RFLAGS", RFLAGS);

    println!("");
    print_register!(vcpu, "RAX", RAX);
    print_register!(vcpu, "RBX", RBX);
    print_register!(vcpu, "RCX", RCX);
    print_register!(vcpu, "RDX", RDX);

    println!("");
    print_register!(vcpu, "RSI", RSI);
    print_register!(vcpu, "RDI", RDI);
    print_register!(vcpu, "RSP", RSP);
    print_register!(vcpu, "RBP", RBP);

    println!("~~~~~ Host State ~~~~");
    // print_vmcs!(vcpu, "CR0", HOST_CR0);
    // print_vmcs!(vcpu, "HOST_CR3", HOST_CR3);
    // print_vmcs!(vcpu, "HOST_CR4", HOST_CR4);

    // println!("");
    // print_vmcs!(vcpu, "HOST_IA32_EFER", HOST_IA32_EFER);

    // print_vmcs!(vcpu, "HOST_FS_BASE", HOST_FS_BASE);
    // print_vmcs!(vcpu, "HOST_GDTR_BASE", HOST_GDTR_BASE);

    // print_vmcs!(vcpu, "HOST_GS_BASE", HOST_GS_BASE);
    // print_vmcs!(vcpu, "HOST_IDTR_BASE", HOST_IDTR_BASE);

    // print_vmcs!(vcpu, "HOST_IA32_PAT", HOST_IA32_PAT);

    // println!("");
    // print_vmcs!(vcpu, "HOST_RIP", HOST_RIP);
    // print_vmcs!(vcpu, "HOST_RSP", HOST_RSP);

    // println!("");
    // print_vmcs!(vcpu, "HOST_ES", HOST_ES);
    // print_vmcs!(vcpu, "HOST_CS", HOST_CS);
    // print_vmcs!(vcpu, "HOST_SS", HOST_SS);
    // print_vmcs!(vcpu, "HOST_DS", HOST_DS);
    // print_vmcs!(vcpu, "HOST_FS", HOST_FS);
    // print_vmcs!(vcpu, "HOST_GS", HOST_GS);

    // println!("");
    // print_vmcs!(vcpu, "HOST_IA32_SYSENTER_CS", HOST_IA32_SYSENTER_CS);
    // print_vmcs!(vcpu, "HOST_IA32_SYSENTER_EIP", HOST_IA32_SYSENTER_EIP);

    println!("~~~~ EO VMCS Dump ~~~");
    Ok(())
}
