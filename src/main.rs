use hv::x86::{VcpuExt, Reg};
// use hv::x86::VcpuExt;
use hv::Error;
use hv::x86::vmx::{VCpuVmxExt, Vmcs};

use inner_vmm::Vmm;

const GUEST_ADDR: usize = 0x0;

fn main() -> Result<(), Error>{
    
	let vmm = Vmm::init()?;
	vmm.load_kernel_img()?;

	let vcpu = &vmm.vcpu;
	
	// Set regs
	vcpu.write_register(Reg::RIP, GUEST_ADDR as _)
		.expect("Failed to set PC reg");
	vcpu.write_register(Reg::RFLAGS, 0x2)
		.expect("Failed to set PC reg");
	vcpu.write_register(Reg::RSP, 0x0)
		.expect("Failed to set PC reg");


	vcpu.write_register(Reg::RAX, 0xFF)
		.expect("Failed to write to RAX");
	vcpu.write_register(Reg::RBX, 0xFF)
		.expect("Failed to write to RAX");

	let rax: u64 = vcpu.read_register(Reg::RAX)
		.expect("Failed to read to RAX");
	let rbx: u64 = vcpu.read_register(Reg::RBX)
		.expect("Failed to read to RAX");

	println!("Avem aicia RAX{:#04x} RBX{:#04x}", rax, rbx);

	for _ in 1..4 {
	
		vcpu.run()?;
		println!("vCPU run");

		let rc = vcpu.read_vmcs(Vmcs::RO_EXIT_REASON)
			.expect("Failed to read exit reason");

			
		// Intel SDE 3C - 27.2.1
		let exit_qual = vcpu.read_vmcs(Vmcs::RO_EXIT_QUALIFIC)
			.expect("Failed to read exit reason");

		println!("Am primit (Exit reason; Exit Qual) ({}, {:#x})", rc, exit_qual);
		// 0111 1000 0100

		// VMCALL
		if rc == 18 {
			println!("Got a VMCALL exit");
			let rip: u64 = vcpu.read_register(Reg::RIP)
			.expect("Failed to read to RIP");

			println!("RIP = [{}]", rip);
		}

		let rax: u64 = vcpu.read_register(Reg::RAX)
			.expect("Failed to read to RAX");
		let rbx: u64 = vcpu.read_register(Reg::RBX)
			.expect("Failed to read to RAX");
		
		println!("Avem aicia RAX{:#04x} RBX{:#04x}", rax, rbx);
		
	}

    Ok(())
}
