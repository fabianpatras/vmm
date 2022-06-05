//! adapted from `rust-cpuid` crate
//! https://github.com/gz/rust-cpuid/blob/d3a34e418f3c8c39575645f0f6f2a7924219f53d/src/lib.rs#L90

#[cfg(all(target_arch = "x86_64", not(target_env = "sgx")))]
use core::arch::x86_64::__cpuid_count;

pub struct CpuIdResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

pub fn cpuid_count(a: u32, c: u32) -> CpuIdResult {
    // Safety: CPUID is supported on all x86_64 CPUs and all x86 CPUs with
    // SSE, but not by SGX.
    let result = unsafe { __cpuid_count(a, c) };

    CpuIdResult {
        eax: result.eax,
        ebx: result.ebx,
        ecx: result.ecx,
        edx: result.edx,
    }
}

// some constants
// See Intel SDM2 Table 3-8
pub const CPUID_1_ECX_HYPERVISOR: u64 = 1 << 31;
pub const CPUID_6_EAX: u64 = 1 << 2;
pub const CPUID_7_0_EBX_SGX_MASK: u64 = 1 << 2;
pub const CPUID_7_0_ECX_SGX_LC_MASK: u64 = 1 << 30;
