// See Intel SDM4 TAble 2-2
// (1 << 0) == Fast-Strings Enable
const MSR_IA32_MISC_ENABLE_DEFAULT: u64 = 1;

// Empty
const MSR_IA32_XSS_DEFAULT: u64 = 0;

pub struct CpuData {
    pub msr_ia32_misc_enable: u64,
    pub msr_ia32_xss: u64,
}

impl Default for CpuData {
    fn default() -> Self {
        CpuData {
            msr_ia32_misc_enable: MSR_IA32_MISC_ENABLE_DEFAULT,
            msr_ia32_xss: MSR_IA32_XSS_DEFAULT,
        }
    }
}
