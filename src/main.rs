// use hv::x86::{VcpuExt, Reg};
// use hv::x86::VcpuExt;
use hv::x86::vmx::{VCpuVmxExt, Vmcs};
use hv::Error;

use hv::x86::VmOptions;

// use inner_vmm::Vmm;

use vm_memory::{GuestAddress, GuestMemoryMmap};

pub mod vcpu;
use crate::vcpu::{HvVcpu, VM_EXIT_VM_ENTRY_FAILURE, X86_IA32_EFER_LMA, X86_IA32_EFER_LME};

// const GUEST_ADDR: usize = 0x0;

const MEM_SIZE: usize = 1024 * 1024 * 1024;

fn main() -> Result<(), Error> {
    let vm = hv::Vm::new(VmOptions::default())?;

    let vcpu = HvVcpu::new(vm).unwrap();

    let guest_memory: GuestMemoryMmap =
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)])
            .expect("Could not init memory with `vm-memory`");

    // vcpu.dump_vmcs()?;
    // vcpu.init(&guest_memory).unwrap();
    println!("init done");


    vcpu.reset().unwrap();
    vcpu.real_mode_setup().unwrap();
    // vcpu.enter_protected_mode(&guest_memory).unwrap();

    // vcpu.test_protected_mode(&guest_memory).unwrap();
    vcpu.dump_vmcs()?;
    vcpu.vcpu.run()?;
    vcpu.dump_vmcs()?;
    // vcpu.dump_vmcs()?;
    let rc = vcpu
        .vcpu
        .read_vmcs(Vmcs::RO_EXIT_REASON)
        .expect("Failed to read exit reason");

    println!("rc = [{:#x}]", rc);
    println!(
        "VM entry failure [{}] exit reason [{}]",
        (rc & VM_EXIT_VM_ENTRY_FAILURE) != 0,
        (rc & !VM_EXIT_VM_ENTRY_FAILURE)
    );

    let efer = vcpu.vcpu.read_vmcs(Vmcs::GUEST_IA32_EFER)?;

    println!("bit LME [{}]", (efer & X86_IA32_EFER_LME) != 0);
    println!("bit LMA [{}]", (efer & X86_IA32_EFER_LMA) != 0);

    // vcpu.test_protected_mode(&guest_memory).unwrap();
    // vcpu.load_kernel(&guest_memory).unwrap();1

    Ok(())
}
