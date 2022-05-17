use hv::x86::{VmOptions, VcpuExt, Reg};
// use hv::x86::VcpuExt;
use hv::Error;
use hv::x86::vmx::{VCpuVmxExt, Vmcs, Capability, read_capability};
use std::sync::Arc;



const MEM_SIZE: usize = 0x100000;
const GUEST_ADDR: usize = 0x0;

static CODE: &[u8] = &[
	0xB8, 0x05, 0x00, // mov ax, 0x05
	0xBB, 0x07, 0x00, // mov bx, 0x07
	0x00, 0xC3, // add bl, al
];

fn cap2ctrl(cap: u64, ctrl: u64) -> u64
{
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

	let proc_desired_cap: u64 = (1 << 7) | (1 << 19) | (1 << 20);

	vmx_cap_entry = cap2ctrl(vmx_cap_entry, 0x0);
	vmx_cap_pinbased = cap2ctrl(vmx_cap_pinbased, 0x0);
	vmx_cap_procbased = cap2ctrl(vmx_cap_procbased, proc_desired_cap);
	vmx_cap_procbased2 = cap2ctrl(vmx_cap_procbased2, 0x0);


	// Vmcs::CTRL_VMENTRY_CONTROLS ????
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
	VCpuVmxExt::write_vmcs(vcpu, Vmcs::GUEST_LDTR_AR, 0x10000)?; // (1<<17)
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


fn main() -> Result<(), Error>{
    
	let vm = Arc::new(hv::Vm::new(VmOptions::default())?);
	println!("VM created");

	let load_addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            MEM_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
            -1,
            0,
        ) as *mut u8
    };

	if load_addr == libc::MAP_FAILED as _ {
        panic!("libc::mmap returned MAP_FAILED");
    }

    unsafe {
        std::ptr::copy_nonoverlapping(CODE.as_ptr(), load_addr, CODE.len());
    }

	vm.map(
        load_addr,
        GUEST_ADDR as _,
        MEM_SIZE as _,
        hv::Memory::READ | hv::Memory::WRITE | hv::Memory::EXEC,
    )?;

	let vcpu: hv::Vcpu = vm.create_cpu()?;
	println!("vCPU created");

	set_up_vcpu(&vcpu)?;
	println!("vCPU write vmcs");
	
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

	for _ in 1..10 {
	
		vcpu.run()?;
		println!("vCPU run");

		let rc = vcpu.read_vmcs(Vmcs::RO_EXIT_REASON)
			.expect("Failed to read exit reason");

		println!("Am primit Exit reason [{}]", rc);
		
		
		let rax: u64 = vcpu.read_register(Reg::RAX)
			.expect("Failed to read to RAX");
		let rbx: u64 = vcpu.read_register(Reg::RBX)
			.expect("Failed to read to RAX");
		
		println!("Avem aicia RAX{:#04x} RBX{:#04x}", rax, rbx);
		
	}

    Ok(())
}
