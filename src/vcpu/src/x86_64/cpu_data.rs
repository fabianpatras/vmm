
// See Intel SDM4 TAble 2-2
// (1 << 0) == Fast-Strings Enable
const MSR_IA32_MISC_ENABLE_DEFAULT: u64 = 1;

pub struct CpuData {
    pub msr_ia32_misc_enable: u64
}

impl Default for CpuData {
    fn default() -> Self {
        CpuData {
            msr_ia32_misc_enable: MSR_IA32_MISC_ENABLE_DEFAULT
        }
    }
}
