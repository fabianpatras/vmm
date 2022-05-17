// use hv::x86::{VcpuExt, Reg};
// use hv::x86::VcpuExt;
use hv::x86::vmx::{VCpuVmxExt, Vmcs};
use hv::Error;
use hv::Memory;

use hv::x86::VmOptions;

// use inner_vmm::Vmm;

use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap};

pub mod vcpu;
use crate::vcpu::{HvVcpu, VM_EXIT_VM_ENTRY_FAILURE, X86_IA32_EFER_LMA, X86_IA32_EFER_LME};

const GUEST_ADDR_START: u64 = 0x00;
const MEM_SIZE: usize = 1024 * 1024 * 1024;

fn main() -> Result<(), Error> {
    let vm = hv::Vm::new(VmOptions::default())?;

    let guest_memory: GuestMemoryMmap =
        GuestMemoryMmap::from_ranges(&[(GuestAddress(GUEST_ADDR_START), MEM_SIZE)])
            .expect("Could not init memory with `vm-memory`");

    for x in guest_memory.iter() {
        // x.as_ptr()
        vm.map(
            x.as_ptr(),
            GUEST_ADDR_START as _,
            MEM_SIZE as _,
            Memory::READ | Memory::WRITE | Memory::EXEC,
        )
        .expect("could not hv_vm_map");
    }

    let vcpu = HvVcpu::new(vm).unwrap();
    // vcpu.init(&guest_memory).unwrap();

    vcpu.real_mode_setup().unwrap();
    vcpu.real_mode_code_test(&guest_memory).unwrap();

    // vcpu.dump_vmcs()?;
    // vcpu.vcpu.run()?;
    // let rc = vcpu
    //     .vcpu
    //     .read_vmcs(Vmcs::RO_EXIT_REASON)
    //     .expect("Failed to read exit reason");

    // println!("rc = [{:#x}]", rc);
    // println!(
    //     "VM entry failure [{}] exit reason [{}]",
    //     (rc & VM_EXIT_VM_ENTRY_FAILURE) != 0,
    //     (rc & !VM_EXIT_VM_ENTRY_FAILURE)
    // );

    // let efer = vcpu.vcpu.read_vmcs(Vmcs::GUEST_IA32_EFER)?;

    // println!("bit LME [{}]", (efer & X86_IA32_EFER_LME) != 0);
    // println!("bit LMA [{}]", (efer & X86_IA32_EFER_LMA) != 0);

    Ok(())
}
