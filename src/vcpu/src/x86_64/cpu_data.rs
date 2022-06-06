// See Intel SDM4 TAble 2-2
// (1 << 0) == Fast-Strings Enable
const MSR_IA32_MISC_ENABLE_DEFAULT: u64 = 1;

// Empty
const MSR_IA32_XSS_DEFAULT: u64 = 0;

// See Intel SDM3A 10.4.4
const APIC_BASE_FIELD: u64 = 0xFEE0_0000 << 12;
const MSR_IA32_APIC_BASE_DEFAULT: u64 = APIC_BASE_FIELD;
const MSR_MISC_FEATURE_ENABLE_DEFAULT: u64 = 0x0;
const MSR_IA32_SPEC_CTRL_DEFAULT: u64 = 0x0;

pub struct CpuData {
    pub msr_ia32_misc_enable: u64,
    pub msr_ia32_xss: u64,
    pub msr_ia32_apic_base: u64,
    pub msr_misc_feature_enable: u64,
    pub msr_ia32_spec_ctrl: u64,
}

impl Default for CpuData {
    fn default() -> Self {
        CpuData {
            msr_ia32_misc_enable: MSR_IA32_MISC_ENABLE_DEFAULT,
            msr_ia32_xss: MSR_IA32_XSS_DEFAULT,
            msr_ia32_apic_base: MSR_IA32_APIC_BASE_DEFAULT,
            msr_misc_feature_enable: MSR_MISC_FEATURE_ENABLE_DEFAULT,
            msr_ia32_spec_ctrl: MSR_IA32_SPEC_CTRL_DEFAULT,
        }
    }
}
