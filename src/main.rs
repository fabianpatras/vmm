extern crate vmm;
use devices::serial::ceva;

const KILO_BYTE: usize = 1024;
const MEGA_BYTE: usize = 1024 * KILO_BYTE;
const GIGA_BYTE: usize = 1024 * MEGA_BYTE;
const MEM_SIZE: usize = 4 * GIGA_BYTE;

const KERNEL_PATH: &str =
    "/Users/ec2-user/repos/vmm/resources/kernel/microvm-kernel-initramfs-hello-x86_64_good";

fn main() -> () {
    let mut vmm = vmm::Vmm::init(0, MEM_SIZE).unwrap();
    vmm.run(KERNEL_PATH).unwrap();
}
