use linux_loader::{
    bootparam::boot_params,
    configurator,
    configurator::{linux::LinuxBootConfigurator, BootConfigurator, BootParams},
    loader,
    loader::{elf::Elf, KernelLoader, KernelLoaderResult},
};
use std::fs::File;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

/// Address of the zeropage, where Linux kernel boot parameters are written.
pub const ZEROPG_START: u64 = 0x7000;
/// Address where the kernel command line is written.
pub const CMDLINE_START: u64 = 0x0002_0000;
/// Default highmem start
pub const HIGHMEM_START_ADDRESS: u64 = 0x10_0000;
/// Default kernel command line.
pub const DEFAULT_KERNEL_CMDLINE: &str = "panic=1 pci=off";

// x86_64 boot pub constants. See https://www.kernel.org/doc/Documentation/x86/boot.txt for the full
// documentation.
// Header field: `boot_flag`. Must contain 0xaa55.
pub const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
// Header field: `header`. Must contain the magic number `HdrS` (0x5372_6448).
pub const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
// Header field: `type_of_loader`.
pub const KERNEL_LOADER_OTHER: u8 = 0xff;
// Header field: `kernel_alignment`. Alignment unit required by a relocatable kernel.
pub const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000;


// Start address for the EBDA (Extended Bios Data Area).
// See https://wiki.osdev.org/Memory_Map_(x86) for more information.
pub const EBDA_START: u64 = 0x0009_fc00;
// RAM memory type.
pub const E820_RAM: u32 = 1;

/// First address past 32 bits is where the MMIO gap ends.
pub const MMIO_GAP_END: u64 = 1 << 32;
/// Size of the MMIO gap.
pub const MMIO_GAP_SIZE: u64 = 768 << 20;
/// The start of the MMIO gap (memory area reserved for MMIO devices).
pub const MMIO_GAP_START: u64 = MMIO_GAP_END - MMIO_GAP_SIZE;


#[derive(Debug)]
pub enum Error {
    FullE820,
    KernelFileNotFound,
    HimemStartPastMemEnd,
    HimemStartPastMmioGapStart,
    MemoryWrite(vm_memory::GuestMemoryError),
    WriteBootParams(configurator::Error),
    Loader(loader::Error),
}


fn add_e820_entry(
    params: &mut boot_params,
    addr: u64,
    size: u64,
    mem_type: u32,
) -> Result<(), Error> {
    if params.e820_entries >= params.e820_table.len() as u8 {
        return Err(Error::FullE820); // TODO: some kind of internal error
    }

    params.e820_table[params.e820_entries as usize].addr = addr;
    params.e820_table[params.e820_entries as usize].size = size;
    params.e820_table[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;

    Ok(())
}

pub fn load_kernel_elf(guest_memory: &GuestMemoryMmap, path: &str) -> Result<KernelLoaderResult, Error> {
    let mut kernel_image = match File::open(path) {
        Ok(file) => {
            file
        },
        Err(_) => {
            return Err(Error::KernelFileNotFound);
        }
    };
    let zero_page_addr = GuestAddress(ZEROPG_START);
    let highmem_start_address = GuestAddress(HIGHMEM_START_ADDRESS);
    let mmio_gap_start = GuestAddress(MMIO_GAP_START);
    let mmio_gap_end = GuestAddress(MMIO_GAP_END);

    // Load the kernel into guest memory.
    let kernel_load = Elf::load(
        guest_memory,
        None,
        &mut kernel_image,
        Some(highmem_start_address),
    ).map_err(Error::Loader)?;

    let mut params = boot_params::default();

    params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.hdr.header = KERNEL_HDR_MAGIC;
    params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;

    if params.hdr.type_of_loader == 0 {
        params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    }

    // Add an entry for EBDA itself.
    add_e820_entry(&mut params, 0, EBDA_START, E820_RAM)?;

    // Add entries for the usable RAM regions (potentially surrounding the MMIO gap).
    let last_addr = guest_memory.last_addr();
    if last_addr < mmio_gap_start {
        add_e820_entry(
            &mut params,
            highmem_start_address.raw_value(),
            // The unchecked + 1 is safe because:
            // * overflow could only occur if last_addr - himem_start == u64::MAX
            // * last_addr is smaller than mmio_gap_start, a valid u64 value
            // * last_addr - himem_start is also smaller than mmio_gap_start
            last_addr
                .checked_offset_from(highmem_start_address)
                .ok_or(Error::HimemStartPastMemEnd)?
                + 1,
            E820_RAM,
        )?;
    } else {
        add_e820_entry(
            &mut params,
            highmem_start_address.raw_value(),
            mmio_gap_start
                .checked_offset_from(highmem_start_address)
                .ok_or(Error::HimemStartPastMmioGapStart)?,
            E820_RAM,
        )?;

        if last_addr > mmio_gap_end {
            add_e820_entry(
                &mut params,
                mmio_gap_end.raw_value(),
                // The unchecked_offset_from is safe, guaranteed by the `if` condition above.
                // The unchecked + 1 is safe because:
                // * overflow could only occur if last_addr == u64::MAX and mmio_gap_end == 0
                // * mmio_gap_end > mmio_gap_start, which is a valid u64 => mmio_gap_end > 0
                last_addr.unchecked_offset_from(mmio_gap_end) + 1,
                E820_RAM,
            )?;
        }
    }

    // Add the kernel command line to the boot parameters.
    params.hdr.cmd_line_ptr = CMDLINE_START as u32;
    params.hdr.cmdline_size = DEFAULT_KERNEL_CMDLINE.len() as u32 + 1;

    guest_memory
        .write_slice(
            DEFAULT_KERNEL_CMDLINE.as_bytes(),
            GuestAddress(CMDLINE_START),
        ).map_err(Error::MemoryWrite)?;

    // Write the boot parameters in the zeropage.
    LinuxBootConfigurator::write_bootparams::<GuestMemoryMmap>(
        &BootParams::new::<boot_params>(&params, zero_page_addr),
        guest_memory,
    ).map_err(Error::WriteBootParams)?; // TODO: error handling

    Ok(kernel_load)
}
