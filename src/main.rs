extern crate vmm;

const KILO_BYTE: usize = 1024;
const MEGA_BYTE: usize = 1024 * KILO_BYTE;
const GIGA_BYTE: usize = 1024 * MEGA_BYTE;
const MEM_SIZE: usize = 2 * GIGA_BYTE;


const KERNEL_PATH: &str = "/Users/ec2-user/repos/vmm/resources/kernel/microvm-kernel-initramfs-hello-x86_64";

fn main() -> () {
    let vmm = vmm::Vmm::init(0, MEM_SIZE).unwrap();
    vmm.run(KERNEL_PATH).unwrap();
}
