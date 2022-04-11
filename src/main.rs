use vm_memory::Bytes;
use vm_memory::GuestAddress;

use vm_memory::{GuestMemory, GuestMemoryMmap};

fn provide_mem_to_virt_dev() {
    let gm: GuestMemoryMmap = vm_memory::GuestMemoryMmap::from_ranges(&[
        (GuestAddress(0), 0x1000),
        (GuestAddress(0x1000), 0x1000),
    ])
    .unwrap();
    virt_device_io(&gm);
}

fn virt_device_io<T: GuestMemory>(mem: &T) {
    let sample_buf: &[u8; 5] = &[1, 2, 3, 4, 5];

    assert_eq!(mem.write(sample_buf, GuestAddress(0xffc)).unwrap(), 5);
    let buf = &mut [0u8; 5];
    assert_eq!(mem.read(buf, GuestAddress(0xffc)).unwrap(), 5);
    assert_eq!(buf, sample_buf);

    println!("Se ruleaza asta!!");
}

#[cfg(target_os = "macos")]
fn hello_world_on_mac() -> () {
    println!("salut din macos!");
}

#[cfg(unix)]
fn hello_world_on_unix() -> () {
    println!("salut din unix!");
}

#[cfg(target_os = "linux")]
fn hello_world_on_linux() -> () {
    println!("salut din linux!");
}

fn main() -> Result<(), hv::Error> {
    println!("Hello, world!");
    use hv::x86::{Capability, VmExt, VmOptions};

    let vm: hv::Vm = hv::Vm::new(VmOptions::default())?;

    println!("Max vCPUs: {}", vm.capability(Capability::VcpuMax)?);

    println!(
        "Available address spaces: {}",
        vm.capability(Capability::AddrSpaceMax)?
    );

    provide_mem_to_virt_dev();

    println!("Salut, test");

    #[cfg(target_os = "macos")]
    hello_world_on_mac();

    #[cfg(unix)]
    hello_world_on_unix();

    #[cfg(target_os = "linux")]
    hello_world_on_linux();

    let machine_kind = if cfg!(unix) {
        "unix"
    } else if cfg!(windows) {
        "windows"
    } else {
        "unknown"
    };

    println!("I'm running on a {} machine!", machine_kind);

    Ok(())
}

// cargo run --features vm-memory/backend-mmap
