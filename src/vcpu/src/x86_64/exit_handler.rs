#[derive(Debug)]
pub enum Error {
    HvReadWrite(hv::Error),

    MsrIndexNotSupportedRead(u32),
    MsrIndexNotSupportedWrite(u32),

    /// eax, ecx
    CpuIdLeafNotSupported(u32, u32),

    CrAccessRegisterNotSupported,
    CrAccessAccessTypeNotSupported,
}

impl From<hv::Error> for Error {
    fn from(err: hv::Error) -> Self {
        Error::HvReadWrite(err)
    }
}
pub trait ExitHandler {
    type E;

    fn handle_cpuid(&self) -> Result<(), Self::E>;
    fn handle_mov_cr(&self) -> Result<(), Self::E>;
    fn handle_msr_access(&self, read: bool) -> Result<(), Self::E>;
}
