#[derive(Debug)]
pub enum Error {
    HvReadWrite(hv::Error),

    // msr access
    MsrIndexNotSupportedRead(u32),
    MsrIndexNotSupportedWrite(u32),

    // cpuid
    /// eax, ecx
    CpuIdLeafNotSupported(u32, u32),

    // control registers access
    CrAccessRegisterNotSupported,
    CrAccessAccessTypeNotSupported,

    // XSETBV write
    XSETBVUnsupportedRegister(u32),
}

impl From<hv::Error> for Error {
    fn from(err: hv::Error) -> Self {
        Error::HvReadWrite(err)
    }
}
pub trait ExitHandler {
    type E;

    fn handle_nmi_interrupt(&self) -> Result<(), Self::E>;
    fn handle_cpuid(&self) -> Result<(), Self::E>;
    fn handle_hlt(&self) -> Result<(), Self::E>;
    fn handle_mov_cr(&self) -> Result<(), Self::E>;
    fn handle_io(&self) -> Result<(), Self::E>;
    fn handle_msr_access(&mut self, read: bool) -> Result<(), Self::E>;
    fn handle_xsetbv(&self) -> Result<(), Self::E>;
}
