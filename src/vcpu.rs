use hv::{
    x86::{
        vmx::{VCpuVmxExt, Vmcs::*},
        Reg::*,
        VcpuExt,
    },
    Error, Vcpu, Vm,
};
use linux_loader::loader::{elf::Elf, KernelLoader};
use std::{
    fs::File,
    io::{BufReader, Read},
    mem,
    sync::Arc,
};
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemory};

/// The offset at which GDT resides in memory.
pub const BOOT_GDT_OFFSET: u64 = 0x500;
/// The offset at which IDT resides in memory.
pub const BOOT_IDT_OFFSET: u64 = 0x520;
/// Maximum number of GDT entries as defined in the Intel Specification.
pub const MAX_GDT_SIZE: usize = 1 << 13;
/// Address of the zeropage, where Linux kernel boot parameters are written.
pub const ZEROPG_START: u64 = 0x7000;

// page map level 4 start offset
const PML4_START: u64 = 0x9000;
//  page-directory-pointer table entry start offset
const PDPTE_START: u64 = 0xA000;
//  page-directory entry start offset
const PDE_START: u64 = 0xB000;

// See Intel SDM3A 2.5
const X86_CR0_PE: u64 = 1 << 0;
const X86_CR0_PG: u64 = 1 << 31;
const X86_CR4_PAE: u64 = 1 << 5;

// See Intel SDM3A 2.2.1 Table 2-1
pub const X86_IA32_EFER_LME: u64 = 1 << 8;
pub const X86_IA32_EFER_LMA: u64 = 1 << 10;

// See Intel SDM3A 4.5.4 Table 4-15
const X86_PLM4E_P: u64 = 1 << 0;
const X86_PLM4E_RW: u64 = 1 << 1;

// See Intel SDM3A 4.5.4 Table 4-17
const X86_PDPTE_P: u64 = 1 << 0;
const X86_PDPTE_RW: u64 = 1 << 1;

// See Intel SDM3A 4.5.4 Table 4-18
const X86_PDE_P: u64 = 1 << 0;
const X86_PDE_RW: u64 = 1 << 1;
const X86_PDE_PS: u64 = 1 << 7;

pub const VM_EXIT_VM_ENTRY_FAILURE: u64 = 1 << 31;

#[derive(Copy, Clone, Default, Debug)]
struct SegmentDescriptor(u64);

unsafe impl ByteValued for SegmentDescriptor {}

struct Gdt(Vec<SegmentDescriptor>);

pub struct HvVcpu {
    pub vcpu: Vcpu,
}

impl SegmentDescriptor {
    // adapted from https://github.com/rust-vmm/vmm-reference/blob/4bae1e1c3261e8edec0958edd786bd13b71fe068/src/vm-vcpu-ref/src/x86_64/gdt.rs#L74
    // see flags at Intel SDM3A 3.4.5
    // this creates a Segment descriptor which is in the form below
    // |63 - - - - - - 56 55 - - 52 51 - -    48 47 - - - - - - 40 39 - - - - - - 32
    // |Base 24:31       | Flags   |Limit 16:19 |  Access Bytes   | Base 16:23     |
    // |31                                    16|15                               0|
    // |          Base 0:15                     |          Limit 0:15              |
    pub fn from(flags: u16, base: u32, limit: u32) -> SegmentDescriptor {
        SegmentDescriptor(
            ((u64::from(base) & 0xff00_0000u64) << (56 - 24))
                | ((u64::from(flags) & 0x0000_f0ffu64) << 40)
                | ((u64::from(limit) & 0x000f_0000u64) << (48 - 16))
                | ((u64::from(base) & 0x00ff_ffffu64) << 16)
                | (u64::from(limit) & 0x0000_ffffu64),
        )
    }
}

impl HvVcpu {
    pub fn new(vm: Vm) -> Result<HvVcpu, Error> {
        let vcpu = Arc::new(vm).create_cpu().unwrap();

        Ok(HvVcpu { vcpu })
    }

    pub fn init<M: GuestMemory>(&self, guest_memory: &M) -> Result<(), Error> {
        // initializare Protected Mode + Long Mode

        // - GDT - Global Descriptor Table
        // - initilizeze GDTR - GDT Register
        // - Control Registers CR1 -> CR4

        // self.vcpu.read_vmcs()




        let null_seg = SegmentDescriptor::from(0, 0, 0);
        let code_seg = SegmentDescriptor::from(0xa09b, 0, 0xfffff);
        let data_seg = SegmentDescriptor::from(0xc093, 0, 0xfffff);
        let tss_seg = SegmentDescriptor::from(0x808b, 0, 0xfffff);

        // println!("code segment DPL [{}]", ((code_seg.0 & 0x0000_6000_0000_0000) >> 45) as u8);
        println!("code segment L bit [{}]", ((code_seg.0 & 0x0020_0000_0000_0000) >> 53) as u8);
        // println!("data segment DPL [{}]", ((data_seg.0 & 0x0000_6000_0000_0000) >> 45) as u8);
        // println!("tss segment DPL [{}]", ((tss_seg.0 & 0x0000_6000_0000_0000) >> 45) as u8);

        let gdt = Gdt(vec![null_seg, code_seg, data_seg, tss_seg]);

        let boot_gdt_addr = GuestAddress(BOOT_GDT_OFFSET);
        for (index, entry) in gdt.0.iter().enumerate() {
            // The multiplication below cannot fail because we can have maximum 8192 entries in
            // the gdt table, and 8192 * 4 (size_of::<u64>) fits in usize
            let addr = guest_memory
                .checked_offset(boot_gdt_addr, index * mem::size_of::<SegmentDescriptor>())
                .unwrap();
            guest_memory.write_obj(*entry, addr).unwrap();
        }

        // adapted from vmm-reference
        self.vcpu
            .write_vmcs(GUEST_GDTR_BASE, BOOT_GDT_OFFSET)
            .unwrap();
        self.vcpu
            .write_vmcs(GUEST_GDTR_LIMIT, std::mem::size_of_val(&gdt) as u64 - 1)
            .unwrap();

        let boot_idt_addr = GuestAddress(BOOT_IDT_OFFSET);
        guest_memory.write_obj(0_u64, boot_idt_addr).unwrap();

        self.vcpu
            .write_vmcs(GUEST_IDTR_BASE, BOOT_IDT_OFFSET)
            .unwrap();
        self.vcpu
            .write_vmcs(GUEST_IDTR_LIMIT, std::mem::size_of::<u64> as u64 - 1)
            .unwrap();

        self.vcpu.write_vmcs(GUEST_CS, code_seg.0).unwrap();
        self.vcpu.write_vmcs(GUEST_DS, data_seg.0).unwrap();
        self.vcpu.write_vmcs(GUEST_ES, data_seg.0).unwrap();
        self.vcpu.write_vmcs(GUEST_FS, data_seg.0).unwrap();
        self.vcpu.write_vmcs(GUEST_GS, data_seg.0).unwrap();
        self.vcpu.write_vmcs(GUEST_SS, data_seg.0).unwrap();
        self.vcpu.write_vmcs(GUEST_TR, tss_seg.0).unwrap();

        // enables Physical Address Extension
        // See Intel SDM3A 4.4.2 Table 4-5
        let cr4 = X86_CR4_PAE;
        self.vcpu.write_vmcs(GUEST_CR4, cr4).unwrap();

        // See Intel SDM3A 2.5
        // When using the physical address extension, the CR3 register contains
        // the base address of the page-directorypointer table.
        let boot_pml4_addr = GuestAddress(PML4_START);

        // See Intel SDM3A 4.5.4 page 4-24
        let cr3 = boot_pml4_addr.raw_value();
        self.vcpu.write_vmcs(GUEST_CR3, cr3).unwrap();

        // see Intel SDM3A
        let boot_pdpte_addr = GuestAddress(PDPTE_START);
        let boot_pde_addr = GuestAddress(PDE_START);

        // See Intel SDM3A 4.5.4 Table 4-15
        // writing a single PLM4 Entry (Page-Directory-Pointer-Table) with Present bit and Write Bit into PML4 Table
        // this refers a region of 512GB
        guest_memory
            .write_obj(
                boot_pdpte_addr.raw_value() | X86_PLM4E_P | X86_PLM4E_RW,
                boot_pml4_addr,
            )
            .unwrap();

        // See Intel SDM3A 4.5.4 Table 4-17
        // writing a single PDPT Entry (Page Directory) with Present bit and Write Bit into PDP Table
        guest_memory
            .write_obj(
                boot_pde_addr.raw_value() | X86_PDPTE_P | X86_PDPTE_RW,
                boot_pdpte_addr,
            )
            .unwrap();

        // See Intel SDM3A 4.5.4 Table 4-18
        // writing 512 2MB Pages with Present bit, Write Bit and Page Size bit into Page Directory
        // This assumes that the CPU supports 2MB pages (`sysctl machdep.cpu.features` has "PSE").
        let page_flags = X86_PDE_P | X86_PDE_RW | X86_PDE_PS;
        for i in 0..512 {
            guest_memory
                .write_obj((i << 21) | page_flags, boot_pde_addr.unchecked_add(i * 8))
                .unwrap();
        }

        // this enables protected mode and paging
        // See Intel SDM3A 2.5 & 9.9.1
        let cr0 = X86_CR0_PE | X86_CR0_PG;
        self.vcpu.write_vmcs(GUEST_CR0, cr0).unwrap();

        // enabling IA-32e mode -> 4-Level Paging
        let mut efer = self.vcpu.read_vmcs(GUEST_IA32_EFER).unwrap();

        println!("EFER    [{:#X}]", efer);
        println!("bit LME [{}]", (efer & X86_IA32_EFER_LME) != 0);
        println!("bit LMA [{}]", (efer & X86_IA32_EFER_LMA) != 0);

        efer |= X86_IA32_EFER_LME;
        self.vcpu.write_vmcs(GUEST_IA32_EFER, efer).unwrap();


        // See Intel SDM3C 24.8 VM-ENTRY CONTROL FIELDS
        let mut vmentry_control = self.vcpu.read_vmcs(CTRL_VMENTRY_CONTROLS).unwrap();
        println!("vm entry control [{:#b}]", vmentry_control);
        let val = 1 << 9;
        vmentry_control |= val;
        println!("vm entry control IA-32e mode guest [{}]", (vmentry_control & (1 << 9)) != 0);
        println!("vm entry control LOAD EFER [{}]", (vmentry_control & (1 << 15)) != 0);

        self.vcpu
            .write_vmcs(CTRL_VMENTRY_CONTROLS, vmentry_control)
            .unwrap();

        // citim din nou vmentry_control
        vmentry_control = self.vcpu.read_vmcs(CTRL_VMENTRY_CONTROLS).unwrap();
        println!("vm entry control [{:#b}]", vmentry_control);

        efer = self.vcpu.read_vmcs(GUEST_IA32_EFER).unwrap();

        println!("bit LME [{}]", (efer & X86_IA32_EFER_LME) != 0);
        println!("bit LMA [{}]", (efer & X86_IA32_EFER_LMA) != 0);

        // let mut cr0_2 = self.vcpu.read_vmcs(GUEST_CR0).unwrap();

        // println!("bit pe [{}]", (cr0_2 & X86_CR0_PE) != 0);
        // println!("bit pg [{}]", (cr0_2 & X86_CR0_PG) != 0);
        // println!(
        //     "code segment L bit [{}]",
        //     ((code_seg.0 & 0x0020_0000_0000_0000) >> 53) as u8
        // );

        let vmentry_interruption_info = self.vcpu.read_vmcs(CTRL_VMENTRY_IRQ_INFO).unwrap();
        println!("vm entry interruption info [{:#b}]", vmentry_interruption_info);

        let rflags = 0x2;
        self.vcpu
            .write_vmcs(GUEST_RFLAGS, rflags)
            .unwrap();

        Ok(())
    }

    pub fn load_kernel<M: GuestMemory>(&self, guest_memory: &M) -> Result<(), Error> {
        let mut kernel_image =
            File::open("/Users/ec2-user/repos/vmm/microvm-kernel-initramfs-hello-x86_64").unwrap();
        let zero_page_addr = GuestAddress(ZEROPG_START);

        // Load the kernel into guest memory.
        let kernel_load = Elf::load(
            guest_memory,
            None,
            &mut kernel_image,
            None, // TODO: change me to something ok
        )
        .unwrap();

        //

        Ok(())
    }

    pub fn test_protected_mode<M: GuestMemory>(&self, guest_memory: &M) -> Result<(), Error> {
        let code_file = File::open("/Users/ec2-user/repos/vmm/test_protected_mode").unwrap();
        
        let mut reader = BufReader::new(code_file);
        let mut buffer = Vec::new();
        
        reader.read_to_end(&mut buffer).unwrap();
        
        let code_address = GuestAddress(0x0010_0000);

        for (idx, value) in buffer.iter().enumerate() {
            let addr = code_address.checked_add(idx as u64).unwrap();
            // println!(
            //     "writing byte [0x{:02X}] to address [0x{:02X}]",
            //     value, addr.0
            // );
            guest_memory.write_obj(*value, addr).unwrap();
        }

        self.vcpu.write_register(RIP, 0x0010_0000).unwrap();
        // let cr0_2 = self.vcpu.read_vmcs(GUEST_CR0).unwrap();

        // println!("-->bit pe [{}]", (cr0_2 & X86_CR0_PE) != 0);
        // println!("-->bit pg [{}]", (cr0_2 & X86_CR0_PG) != 0);
        

        let cr0_mask = self.vcpu.read_shadow_vmcs(CTRL_CR0_MASK).unwrap();
        let cr0_shadow = self.vcpu.read_shadow_vmcs(CTRL_CR0_SHADOW).unwrap();
        
        println!("CR0 MASK [{:x}]", cr0_mask);
        println!("CR0 SHADOW [{:x}]", cr0_shadow);

        // for _ in 1..2 {
            let res = self.vcpu.run();
            println!("{:?}", res);
            res.unwrap();
            let rc = self
                .vcpu
                .read_vmcs(RO_EXIT_REASON)
                .expect("Failed to read exit reason");

            println!("rc = [{}]", rc);

            println!(
                "VM entry failure [{}]",
                (rc & VM_EXIT_VM_ENTRY_FAILURE) != 0
            );
            println!(
                "VM entry exit code [{:#?}]",
                (rc ^ VM_EXIT_VM_ENTRY_FAILURE)
            );

            // Intel SDE 3C - 27.2.1
            let exit_qual = self
                .vcpu
                .read_vmcs(RO_EXIT_QUALIFIC)
                .expect("Failed to read exit reason");

            println!(
                "Am primit (Exit reason; Exit Qual) ({:#x}, {:#x})",
                rc, exit_qual
            );
            // 0111 1000 0100

            let rax = self
                .vcpu
                .read_register(RAX)
                .expect("Failed to read exit reason");

            println!("Avem RAX = [0x{:X}]", rax);
            let rip = self
                .vcpu
                .read_register(RIP)
                .expect("Failed to read exit reason");

            println!("Avem RIP = [0x{:X}]", rip);
        // }

        Ok(())
    }
}
