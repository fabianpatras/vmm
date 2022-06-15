use vm_device::{
    bus::{PioAddress, PioRange},
    device_manager::{IoManager, PioManager},
    MutDevicePio,
};
use vm_superio::{serial::NoEvents, Serial, Trigger};

use kqueue::Event as KqEvent;

use std::io;
use std::io::stdin;
use std::io::Read;
use std::sync::Arc;
use std::sync::Mutex;

pub struct KqEventTrigger(pub u64);

#[derive(Debug)]
pub enum Error {
    // NoError,
}

impl KqEventTrigger {
    pub fn write(&self, _data: u64) -> () {
        // println!("Scriu [{}]", data);
    }
}

pub struct SerialWrapper(pub Serial<KqEventTrigger, NoEvents, io::Stdout>);

impl Trigger for KqEventTrigger {
    type E = Error;

    fn trigger(&self) -> Result<(), Self::E> {
        println!("DummyTrigger triggered");
        self.write(1);

        Ok(())
    }
}

impl MutDevicePio for SerialWrapper {
    fn pio_read(
        &mut self,
        _base: vm_device::bus::PioAddress,
        offset: vm_device::bus::PioAddressOffset,
        data: &mut [u8],
    ) {
        // println!("citim");

        if self.0.fifo_capacity() == 0x40 {
            let mut out = [0u8; 32];
            match stdin().read(&mut out) {
                Ok(count) => {
                    if count > 0 {
                        if self.0.enqueue_raw_bytes(&out[..count]).is_err() {
                            eprintln!("Failed to send bytes to the guest via serial input");
                        }
                    }
                }
                Err(e) => {
                    panic!("error reading from stdin [{}]", e);
                }
            }
        }

        data[0] = self.0.read((offset & 0xFF) as u8);
        println!("citim [{:#x}] de pe offset [{}]", data[0], offset);
    }

    fn pio_write(
        &mut self,
        _base: vm_device::bus::PioAddress,
        offset: vm_device::bus::PioAddressOffset,
        data: &[u8],
    ) {
        // println!("scriem");
        match self.0.write((offset & 0xFF) as u8, data[0]) {
            Err(e) => {
                println!("erro [{:?}]", e);
            }
            _ => {}
        }
    }
}

// pub fn ceva() -> () {

//     let my_trigger = KqEventTrigger {};
//     let my_serial = Arc::new(Mutex::new(SerialWrapper(Serial::new(
//         my_trigger,
//         io::stdout(),
//     ))));

//     let mut manager = IoManager::new();
//     let bus_range = PioRange::new(PioAddress(0), 10).unwrap();
//     manager.register_pio(bus_range, my_serial.clone()).unwrap();
//     manager
//         .pio_write(PioAddress(0), &vec![b'o', b'k', b'o', b'k', b'o', b'k'])
//         .unwrap();
// }
