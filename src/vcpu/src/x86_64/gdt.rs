// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vm_memory::ByteValued;

#[derive(Copy, Clone, Default, Debug)]
pub struct SegmentDescriptor(u64);

unsafe impl ByteValued for SegmentDescriptor {}

pub struct Gdt(pub Vec<SegmentDescriptor>);

impl SegmentDescriptor {
    // adapted from https://github.com/rust-vmm/vmm-reference/blob/4bae1e1c3261e8edec0958edd786bd13b71fe068/src/vm-vcpu-ref/src/x86_64/gdt.rs#L74
    // see flags at Intel SDM3A 3.4.5
    // this creates a Segment descriptor which is in the form below
    // |63 - - - - - - 56 55 - - 52 51 - -    48 47 - - - - - - 40 39 - - - - - - 32
    // |Base 24:31       | Flags   |Limit 16:19 |  Access Bytes   | Base 16:23     |
    // |31                                    16|15                               0|
    // |          Base 0:15                     |          Limit 0:15              |
    pub fn from(flags: u16, base: u32, limit: u32) -> SegmentDescriptor {
        SegmentDescriptor(
            ((u64::from(base) & 0xff00_0000u64) << (56 - 24))
                | ((u64::from(flags) & 0x0000_f0ffu64) << 40)
                | ((u64::from(limit) & 0x000f_0000u64) << (48 - 16))
                | ((u64::from(base) & 0x00ff_ffffu64) << 16)
                | (u64::from(limit) & 0x0000_ffffu64),
        )
    }
}
