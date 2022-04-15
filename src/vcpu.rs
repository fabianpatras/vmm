
use hv::{Vcpu, Vm};


struct Regs {
    eax: u64,
}

struct Segment {

}

struct SegmentRegs {

}

struct HvVcpu {
    vcpu: Vcpu,
}


impl HvVcpu {
    pub fn new(vm: &Vm) -> Result<HvVcpu> {
        let vcpu = vm.create_cpu()?;


        Ok(HvVcpu {
            vcpu
        })
    }

    pub fn init(&self) -> Result<()> {
        // initializare Protected Mode + Long Mode

        // - GDT - Global Descriptor Table
        // - initilizeze GDTR - GDT Register
	    // - Control Registers CR1 -> CR4



        Ok()
    }

}


