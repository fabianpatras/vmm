extern crate vmm;

const KILO_BYTE: usize = 1024;
const MEGA_BYTE: usize = 1024 * KILO_BYTE;
const GIGA_BYTE: usize = 1024 * MEGA_BYTE;
const MEM_SIZE: usize = 4 * GIGA_BYTE;

// const KERNEL_PATH: &str = "/Users/ec2-user/repos/vmm/resources/kernel/microvm-kernel-initramfs-hello-x86_64";
// const KERNEL_PATH: &str = "/Users/ec2-user/repos/vmm/resources/kernel/vmlinux_x86_64_tiny_kernel";
// const KERNEL_PATH: &str = "/Users/ec2-user/repos/vmm/resources/kernel/vmlinux_x86_64_tiny_kernel_halt1_v3";
// const KERNEL_PATH: &str = "/Users/ec2-user/repos/vmm/resources/kernel/vmlinux_x86_64_tiny_kernel_debug";
// const KERNEL_PATH: &str = "/Users/ec2-user/repos/vmm/resources/kernel/vmlinux_from_vmm_reference";
const KERNEL_PATH: &str =
    "/Users/ec2-user/repos/vmm/resources/kernel/vmlinux_from_vmm_reference_prints";

fn main() -> () {
    let mut vmm = vmm::Vmm::init(0, MEM_SIZE).unwrap();
    vmm.run(KERNEL_PATH).unwrap();
}
