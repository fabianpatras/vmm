use hv::x86::vmx::{read_capability, Capability, VCpuVmxExt, Vmcs};
use hv::x86::VmOptions;
use hv::{Error, Memory, Vcpu};
use linux_loader::loader::KernelLoader;
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};
// use libc;
use std::sync::Arc;

use linux_loader::loader::elf::Elf as Loader;
use std::fs::File;
use std::result::Result;

#[allow(dead_code)]

pub struct KernelCfg {
    // pub
    something: u64,
}

pub struct Vmm {
    // guest address space
    pub guest_memory: GuestMemoryMmap,
    // virtual CPUs
    pub vcpu: Vcpu,
    pub kernel_cgf: KernelCfg,
}

const MEGA_BYTE: usize = 1024 * 1024;
const MEM_SIZE: usize = 512 * MEGA_BYTE;
const GUEST_ADDR: usize = 0x0;

// const DEFAULT_KERNEL_ADDRESS: GuestAddress = GuestAddress(0x200000);

static CODE: &[u8] = &[
    0xB8, 0x05, 0x00, // mov ax, 0x05
    // 0xF4, 					// hlt
    0xBB, 0x07, 0x00, // mov bx, 0x07
    0x0F, 0x01, 0xC1, // VMCALL -> creates a VM Exit
    0x00, 0xC3, // add bl, al
];

fn cap2ctrl(cap: u64, ctrl: u64) -> u64 {
    (ctrl | (cap & 0xffffffff)) & (cap >> 32)
}

fn set_up_vcpu(vcpu: &hv::Vcpu) -> Result<(), Error> {
    let mut vmx_cap_entry: u64;
    let mut vmx_cap_pinbased: u64;
    let mut vmx_cap_procbased: u64;
    let mut vmx_cap_procbased2: u64;

    // grep -R 'VMCS_GUEST_CS_LIMIT'
    // find / -name hv_vmx.h
    // /Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/Frameworks/Hypervisor.framework/Versions/A/Headers/hv_arch_vmx.h

    vmx_cap_entry = read_capability(Capability::Entry)?;
    vmx_cap_pinbased = read_capability(Capability::PinBased)?;
    vmx_cap_procbased = read_capability(Capability::ProcBased)?;
    vmx_cap_procbased2 = read_capability(Capability::ProcBased2)?;

    // TODO: what are these?
    let proc_desired_cap: u64 = (1 << 7) | (1 << 19) | (1 << 20);

    vmx_cap_entry = cap2ctrl(vmx_cap_entry, 0x0);
    vmx_cap_pinbased = cap2ctrl(vmx_cap_pinbased, 0x0);
    vmx_cap_procbased = cap2ctrl(vmx_cap_procbased, proc_desired_cap);
    vmx_cap_procbased2 = cap2ctrl(vmx_cap_procbased2, 0x0);

    VCpuVmxExt::write_vmcs(vcpu, Vmcs::CTRL_VMENTRY_CONTROLS, vmx_cap_entry)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::CTRL_PIN_BASED, vmx_cap_pinbased)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::CTRL_CPU_BASED, vmx_cap_procbased)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::CTRL_CPU_BASED2, vmx_cap_procbased2)?;

    VCpuVmxExt::write_vmcs(vcpu, Vmcs::CTRL_EXC_BITMAP, 0x0)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::CTRL_CR0_MASK, 0x60000000)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::CTRL_CR0_SHADOW, 0x0)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::CTRL_CR4_MASK, 0x0)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::CTRL_CR4_SHADOW, 0x0)?;

    // Code segment
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_CS, 0x0)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_CS_LIMIT, 0xffff)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_CS_AR, 0x9b)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_CS_BASE, 0x0)?;

    // Data segment
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_DS, 0x0)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_DS_LIMIT, 0xffff)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_DS_AR, 0x93)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_DS_BASE, 0x0)?;

    // Stack segment
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_SS, 0x0)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_SS_LIMIT, 0xffff)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_SS_AR, 0x93)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_SS_BASE, 0x0)?;

    // Extra segment
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_ES, 0x0)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_ES_LIMIT, 0xffff)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_ES_AR, 0x93)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_ES_BASE, 0x0)?;

    // F segment
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_FS, 0x0)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_FS_LIMIT, 0xffff)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_FS_AR, 0x93)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_FS_BASE, 0x0)?;

    // G segment
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_GS, 0x0)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_GS_LIMIT, 0xffff)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_GS_AR, 0x93)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_GS_BASE, 0x0)?;

    // Task state segment
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_TR, 0x0)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_TR_LIMIT, 0xffff)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_TR_AR, 0x83)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_TR_BASE, 0x0)?;

    // Local Descriptor Table
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_LDTR, 0x0)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_LDTR_LIMIT, 0x0)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_LDTR_AR, 0x10000)?; // (1 << 17)
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_LDTR_BASE, 0x0)?;

    // GDTR Global Description Table Register
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_GDTR_LIMIT, 0x0)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_GDTR_BASE, 0x0)?;

    // IDTR Interrupt Description Table Register
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_IDTR_LIMIT, 0x0)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_IDTR_BASE, 0x0)?;

    // CR stuff
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_CR0, 0x20)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_CR3, 0x0)?;
    VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_CR4, 0x2000)?; // CR4.VMXE = (1 << 13)

    Ok(())
}

impl Vmm {
    pub fn init() -> Result<Self, Error> {
        let vm = Arc::new(hv::Vm::new(VmOptions::default())?);
        println!("VM created");

        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        let load_addr: GuestMemoryMmap =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)])
                .expect("Could not init memory with `vm-memory`");

        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        assert!(load_addr.iter().count() == 1);

        for x in load_addr.iter() {
            // x.as_ptr()
            vm.map(
                x.as_ptr(),
                GUEST_ADDR as _,
                MEM_SIZE as _,
                Memory::READ | Memory::WRITE | Memory::EXEC,
            )
            .expect("could not hv_vm_map");
        }

        load_addr
            .write(CODE, GuestAddress(0x00))
            .expect("Could not write CODE to guest memory");

        // vm.map(
        //     load_addr.iter(),
        // 	load_addr.last_addr(),
        //     GUEST_ADDR as _,
        //     MEM_SIZE as _,
        //     hv::Memory::READ | hv::Memory::WRITE | hv::Memory::EXEC,
        // )?;

        let vcpu: hv::Vcpu = vm.create_cpu()?;
        println!("vCPU created");
        set_up_vcpu(&vcpu)?;

        Ok(Vmm {
            guest_memory: load_addr,
            vcpu,
            kernel_cgf: KernelCfg { something: 0 },
        })
    }

    pub fn load_kernel_img(&self) -> Result<(), Error> {
        let mut kernel_file: File =
            File::open("/Users/ec2-user/repos/vmm/microvm-kernel-initramfs-hello-x86_64").unwrap();

        let loader_result = Loader::load(
            &self.guest_memory,
            None, // not mandatory
            &mut kernel_file,
            None,
        )
        .unwrap();

        println!("Hai k am incarcat kernelul??");

        match loader_result.setup_header {
            Some(x) => println!("{:?}", x),
            None => println!("None setup_header"),
        }

        println!("PVH_boot_cap [{}]", loader_result.pvh_boot_cap);
        // self.vcpu.write_register(Reg::, value)

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
