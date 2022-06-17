use vm::HvVm;
use vm_memory::{GuestAddress, GuestMemoryMmap};
mod bootloader;
use crate::bootloader::load_kernel_elf;
pub struct Vmm {
    pub vm: HvVm,
    pub guest_memory: GuestMemoryMmap,
}

#[derive(Debug)]
pub enum Error {
    /// Error caused by `vm` crate
    Vm(vm::Error),
    /// Error caused by `vm_memory` crate
    Memory(vm_memory::Error),

    Bootloader(bootloader::Error),
}

impl Vmm {
    pub fn init(mem_start_address: usize, mem_size: usize) -> Result<Vmm, Error> {
        let mut vm = HvVm::init().map_err(Error::Vm)?;
        let guest_memory: GuestMemoryMmap = GuestMemoryMmap::from_ranges(&[(
            GuestAddress(mem_start_address as u64),
            mem_size as usize,
        )])
        .map_err(Error::Memory)?;

        vm.map_memory(&guest_memory, mem_start_address, mem_size)
            .map_err(Error::Vm)?;

        vm.create_cpu(&guest_memory).map_err(Error::Vm)?;

        Ok(Vmm { vm, guest_memory })
    }

    pub fn run(&mut self, kernel_path: &str) -> Result<(), Error> {
        let kernel_result =
            load_kernel_elf(&self.guest_memory, kernel_path).map_err(Error::Bootloader)?;

        self.vm
            .run(kernel_result.kernel_load.0, &self.guest_memory)
            .map_err(Error::Vm)?;

        Ok(())
    }
}
