mod bootloader;

use crate::bootloader::load_kernel_elf;

use devices::serial::{KqEventTrigger, SerialWrapper};
use vm::HvVm;

use vm_device::{
    bus::{PioAddress, PioRange},
    device_manager::{IoManager, PioManager},
    MutDevicePio,
};
use vm_memory::{GuestAddress, GuestMemoryMmap};
use vm_superio::{serial::NoEvents, Serial, Trigger};

use vmm_sys_util::terminal::Terminal;

use kqueue::Event;
use kqueue::Watcher;
use kqueue::Ident::Fd;

use std::io;
use std::io::stdin;
use std::os::unix::prelude::RawFd;
use std::sync::Arc;
use std::sync::Mutex;

pub struct Vmm {
    pub vm: HvVm,
    pub guest_memory: GuestMemoryMmap,
    pub device_manager: Arc<Mutex<IoManager>>,
    pub watcher: Arc<Mutex<Watcher>>,
}

#[derive(Debug)]
pub enum Error {
    /// Error caused by `vm` crate
    Vm(vm::Error),
    /// Error caused by `vm_memory` crate
    Memory(vm_memory::Error),

    Bootloader(bootloader::Error),

    SerialDevice,

    Kqueue(io::Error),
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

        let watcher = Arc::new(Mutex::new(Watcher::new().map_err(Error::Kqueue)?));

        let vmm = Vmm {
            vm,
            guest_memory,
            device_manager,
            watcher,
        };

        vmm.add_serial_console();

        Ok(vmm)
    }

    pub fn run(&mut self, kernel_path: &str) -> Result<(), Error> {
        let kernel_result =
            load_kernel_elf(&self.guest_memory, kernel_path).map_err(Error::Bootloader)?;

        // if stdin().lock().set_raw_mode().is_err() {
        //     eprintln!("Failed to set raw mode on terminal. Stdin will echo.");
        // }

        // this should spawn a thread (vcpu)
        self.vm
            .run(kernel_result.kernel_load.0, &self.guest_memory)
            .map_err(Error::Vm)?;

        
        loop {
            match self.watcher.lock().unwrap().poll_forever(None) {
                None => {
                    println!("ce??");break;
                }
                Some(e) => {
                    match e.ident {
                        Fd(fd) => {

                        }
                        _ => {
                            println!("I should not see this?");
                        }
                    }
                    println!("Got event [{:?}]", e.ident);
                }
            }
        }


        Ok(())
    }

    fn add_serial_console(&self) {
        let terminal_fd = stdin().lock().tty_fd() as RawFd;

        self.watcher.lock().unwrap().add_fd(terminal_fd, kqueue::EventFilter::EVFILT_READ, kqueue::FilterFlag::NOTE_FFNOP).unwrap();

        let dummy_trigger = KqEventTrigger(0);
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
