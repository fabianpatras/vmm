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

    vcpu.init(&guest_memory).unwrap();
    println!("init done");


    // let vmentry_control = vcpu.vcpu.read_vmcs(Vmcs::CTRL_VMENTRY_CONTROLS)?;

    // println!("-->vm entry control [{:b}]", vmentry_control);
    // 1001 0001 1111 1111
    //        |

    // vcpu.test_protected_mode(&guest_memory).unwrap();
    vcpu.vcpu.run()?;
    println!("after this?");
    let rc = vcpu
        .vcpu
        .read_vmcs(Vmcs::RO_EXIT_REASON)
        .expect("Failed to read exit reason");

    println!("rc = [{:#x}]", rc);
    println!("VM entry failure [{}]", (rc ^ VM_EXIT_VM_ENTRY_FAILURE));

    let efer = vcpu.vcpu.read_vmcs(Vmcs::GUEST_IA32_EFER)?;

    println!("bit LME [{}]", (efer & X86_IA32_EFER_LME) != 0);
    println!("bit LMA [{}]", (efer & X86_IA32_EFER_LMA) != 0);

    // vcpu.test_protected_mode(&guest_memory).unwrap();
    // vcpu.load_kernel(&guest_memory).unwrap();1

    // // Set regs
    // vcpu.write_register(Reg::RIP, GUEST_ADDR as _)
    // 	.expect("Failed to set PC reg");
    // vcpu.write_register(Reg::RFLAGS, 0x2)
    // 	.expect("Failed to set PC reg");
    // vcpu.write_register(Reg::RSP, 0x0)
    // 	.expect("Failed to set PC reg");

    // vcpu.write_register(Reg::RAX, 0xFF)
    // 	.expect("Failed to write to RAX");
    // vcpu.write_register(Reg::RBX, 0xFF)
    // 	.expect("Failed to write to RAX");

    // let rax: u64 = vcpu.read_register(Reg::RAX)
    // 	.expect("Failed to read to RAX");
    // let rbx: u64 = vcpu.read_register(Reg::RBX)
    // 	.expect("Failed to read to RAX");

    // println!("Avem aicia RAX{:#04x} RBX{:#04x}", rax, rbx);

    // for _ in 1..4 {

    // 	vcpu.run()?;
    // 	println!("vCPU run");

    // 	let rc = vcpu.read_vmcs(Vmcs::RO_EXIT_REASON)
    // 		.expect("Failed to read exit reason");

    // 	// Intel SDE 3C - 27.2.1
    // 	let exit_qual = vcpu.read_vmcs(Vmcs::RO_EXIT_QUALIFIC)
    // 		.expect("Failed to read exit reason");

    // 	println!("Am primit (Exit reason; Exit Qual) ({}, {:#x})", rc, exit_qual);
    // 	// 0111 1000 0100

    // 	// VMCALL
    // 	if rc == 18 {
    // 		println!("Got a VMCALL exit");
    // 		let rip: u64 = vcpu.read_register(Reg::RIP)
    // 		.expect("Failed to read to RIP");

    // 		println!("RIP = [{}]", rip);
    // 	}

    // 	let rax: u64 = vcpu.read_register(Reg::RAX)
    // 		.expect("Failed to read to RAX");
    // 	let rbx: u64 = vcpu.read_register(Reg::RBX)
    // 		.expect("Failed to read to RAX");

    // 	println!("Avem aicia RAX{:#04x} RBX{:#04x}", rax, rbx);

    // }

    Ok(())
}
