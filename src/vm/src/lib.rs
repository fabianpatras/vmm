use hv::{x86::VmOptions, Memory, Vm};
use std::sync::Arc;
use vcpu::x86_64::vcpu::{Error as HvVcpuError, HvVcpu};
use vm_memory::{GuestMemory, GuestMemoryMmap};

pub struct HvVm {
    pub hv_vm: Arc<Vm>,
    pub vcpus: Vec<HvVcpu>,
}

#[derive(Debug)]
pub enum Error {
    /// Error caused by `hv` framework while creating Vm
    HvCreateVm(hv::Error),
    /// Error caused by `hv` framework while manipulating memory
    MapMemory(hv::Error),
    /// Error caused by `guest_memory` not having exactly one region
    MapMemoryNotExactlyOneRegion,
    /// Error caused by `hv` framework while creating vCPU
    CreateHvVcpu(HvVcpuError),
    /// Error caused while trying to set RIP
    SetPaging(HvVcpuError),
    /// Error caused while trying to set RIP
    SetRip(HvVcpuError),
    /// Error caused by not handling VM exits (or `hv` fails)
    RunVcpu(HvVcpuError), // perhaps these kind of errors like setting rip should alredy come form the
                          // vcpu side :thinking:
}

impl HvVm {
    pub fn init() -> Result<HvVm, Error> {
        let vm = Vm::new(VmOptions::default()).map_err(Error::HvCreateVm)?;

        let hv_vm = Arc::new(vm);

        Ok(HvVm {
            hv_vm,
            vcpus: Vec::new(),
        })
    }

    pub fn map_memory(
        &self,
        guest_memory: &GuestMemoryMmap,
        mem_start_address: usize,
        mem_size: usize,
    ) -> Result<(), Error> {
        // we're only expecting one contiguous region at this time
        if guest_memory.iter().count() != 1 {
            return Err(Error::MapMemoryNotExactlyOneRegion);
        }

        for x in guest_memory.iter() {
            self.hv_vm
                .map(
                    x.as_ptr(),
                    mem_start_address as _,
                    mem_size as _,
                    Memory::READ | Memory::WRITE | Memory::EXEC,
                )
                .map_err(Error::MapMemory)?;
        }

        Ok(())
    }

    pub fn create_cpu<M: GuestMemory>(&mut self, guest_memory: &M) -> Result<(), Error> {
        let vcpu =
            HvVcpu::new(Arc::clone(&self.hv_vm), guest_memory).map_err(Error::CreateHvVcpu)?;

        self.vcpus.push(vcpu);

        Ok(())
    }

    pub fn run<M: GuestMemory>(&mut self, rip: u64, guest_memory: &M) -> Result<(), Error> {
        self.vcpus[0]
            .paging_mode_setup_4_level(guest_memory)
            .map_err(Error::SetPaging)?;
        self.vcpus[0]
            .set_regs_for_boot(rip)
            .map_err(Error::SetRip)?;
        match self.vcpus[0].run().map_err(Error::RunVcpu) {
            Ok(_) => {
                self.vcpus[0]
                    .print_exit_instruction(guest_memory)
                    .map_err(Error::RunVcpu)?;
            }
            Err(Error::RunVcpu(HvVcpuError::ExitHandler(e))) => {
                println!("Exit handler Error {:#?}", e);
                // self.vcpus[0].dump_vcpu_state().unwrap();
                self.vcpus[0]
                    .print_exit_instruction(guest_memory)
                    .map_err(Error::RunVcpu)?;
            }
            Err(e) => {
                println!("HV error?\n[{:#?}]", e);
                self.vcpus[0].dump_vcpu_state().unwrap();
                self.vcpus[0]
                    .print_exit_instruction(guest_memory)
                    .map_err(Error::RunVcpu)?;
            }
        };

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
