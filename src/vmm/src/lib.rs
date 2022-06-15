mod bootloader;

use crate::bootloader::load_kernel_elf;

use devices::serial::{DummyTrigger, SerialWrapper};
use vm::HvVm;

use vm_device::{
    bus::{PioAddress, PioRange},
    device_manager::{IoManager, PioManager},
    MutDevicePio,
};
use vm_memory::{GuestAddress, GuestMemoryMmap};
use vm_superio::{serial::NoEvents, Serial, Trigger};

use std::io;
use std::sync::Arc;
use std::sync::Mutex;

pub struct Vmm {
    pub vm: HvVm,
    pub guest_memory: GuestMemoryMmap,
    pub device_manager: Arc<Mutex<IoManager>>,
}

#[derive(Debug)]
pub enum Error {
    /// Error caused by `vm` crate
    Vm(vm::Error),
    /// Error caused by `vm_memory` crate
    Memory(vm_memory::Error),

    Bootloader(bootloader::Error),

    SerialDevice,
}

impl Vmm {
    pub fn init(mem_start_address: usize, mem_size: usize) -> Result<Vmm, Error> {
        let mut vm = HvVm::init().map_err(Error::Vm)?;
        let guest_memory: GuestMemoryMmap = GuestMemoryMmap::from_ranges(&[(
            GuestAddress(mem_start_address as u64),
            mem_size as usize,
        )])
        .map_err(Error::Memory)?;
        let device_manager = Arc::new(Mutex::new(IoManager::new()));

        vm.map_memory(&guest_memory, mem_start_address, mem_size)
            .map_err(Error::Vm)?;

        vm.create_cpu(&guest_memory, device_manager.clone())
            .map_err(Error::Vm)?;

        let vmm = Vmm {
            vm,
            guest_memory,
            device_manager,
        };
        vmm.add_serial_console();

        Ok(vmm)
    }

    pub fn run(&mut self, kernel_path: &str) -> Result<(), Error> {
        let kernel_result =
            load_kernel_elf(&self.guest_memory, kernel_path).map_err(Error::Bootloader)?;

        self.vm
            .run(kernel_result.kernel_load.0, &self.guest_memory)
            .map_err(Error::Vm)?;

        Ok(())
    }

    fn add_serial_console(&self) {
        let dummy_trigger = DummyTrigger {};
        let serial_device = Arc::new(Mutex::new(SerialWrapper(Serial::new(
            dummy_trigger,
            io::stdout(),
        ))));

        // See https://wiki.osdev.org/Serial_Ports
        // We're setting up COM1 (ttyS0)
        let bus_range = PioRange::new(PioAddress(0x3F8), 0x8).unwrap();
        self.device_manager
            .lock()
            .unwrap()
            .register_pio(bus_range, serial_device)
            .unwrap();
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
