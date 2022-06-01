use hv::x86::{VcpuExt, Reg};
// use hv::x86::VcpuExt;
use hv::Error;
use hv::Memory;

use hv::x86::VmOptions;

// use inner_vmm::Vmm;

use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap};

pub mod vcpu;
use crate::vcpu::HvVcpu;

const GUEST_ADDR_START: u64 = 0x00;
const KILO_BYTE: usize = 1024;
const MEGA_BYTE: usize = 1024 * KILO_BYTE;
const GIGA_BYTE: usize = 1024 * MEGA_BYTE;
const MEM_SIZE: usize = 2 * GIGA_BYTE;

fn main() -> Result<(), Error> {
    let vm = hv::Vm::new(VmOptions::default())?;

    let guest_memory: GuestMemoryMmap =
        GuestMemoryMmap::from_ranges(&[(GuestAddress(GUEST_ADDR_START), MEM_SIZE)])
            .expect("Could not init memory with `vm-memory`");

    assert!(guest_memory.iter().count() == 1);

    for x in guest_memory.iter() {
        vm.map(
            x.as_ptr(),
            GUEST_ADDR_START as _,
            MEM_SIZE as _,
            Memory::READ | Memory::WRITE | Memory::EXEC,
        )
        .expect("could not hv_vm_map");
    }

    let vcpu = HvVcpu::new(vm).unwrap();

    vcpu.protected_mode_setup(&guest_memory).unwrap();
    vcpu.paging_mode_setup_4_level(&guest_memory).unwrap();

    // vcpu.real_mode_code_test(&guest_memory).unwrap();

    vcpu.load_kernel_elf(
        &guest_memory,
        "/Users/ec2-user/repos/vmm/resources/kernel/microvm-kernel-initramfs-hello-x86_64",
    )
    .unwrap();
    // vcpu.load_kernel_bzimage(&guest_memory).unwrap();

    match vcpu.run_cpu_handle_exits() {
        Err(x) => println!("Err [{}] at RIP [{:#X}]", x, vcpu.vcpu.read_register(Reg::RIP).unwrap()),
        Ok(_) => {}
    }
    // vcpu.dump_vmcs().unwrap();
    // vcpu.print_exit_instruction(&guest_memory).unwrap();

    Ok(())
}
