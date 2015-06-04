use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Class(pub u16);
pub const PECLASSROM: Class = Class(0x107);
pub const PECLASS32: Class = Class(0x10B);
pub const PECLASS64: Class = Class(0x20B);

impl fmt::Debug for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            PECLASSROM => "ROM",
            PECLASS32 => "32-bit",
            PECLASS64 => "64-bit",
            _ => "unknown",
        };
        write!(f, "{}", str)
    }
}

/// PE file machine architecture
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Machine(pub u16);
/// Invalid machine architecture
pub const PM_UNKNOWN: Machine = Machine(0x0);
/// Matsushita AM33
pub const PM_AM33: Machine = Machine(0x1d3);
/// x64
pub const PM_AMD6: Machine = Machine(0x8664);
/// ARM little endian
pub const PM_ARM: Machine = Machine(0x1c0);
/// ARMv7 (or higher) Thumb mode only
pub const PM_ARMNT: Machine = Machine(0x1c4);
/// ARMv8 in 64-bit mode
pub const PM_ARM64: Machine = Machine(0xaa64);
/// EFI byte code
pub const PM_EBC: Machine = Machine(0xebc);
/// Intel 386 or later processors and compatible processors
pub const PM_I386: Machine = Machine(0x14c);
/// Intel Itanium processor family
pub const PM_IA64: Machine = Machine(0x200);
/// Mitsubishi M32R little endian
pub const PM_M32R: Machine = Machine(0x9041);
/// MIPS16
pub const PM_MIPS16: Machine = Machine(0x266);
/// MIPS with FPU
pub const PM_MIPSFPU: Machine = Machine(0x366);
/// MIPS16 with FPU
pub const PM_MIPSFPU16: Machine = Machine(0x466);
/// Power PC little endian
pub const PM_POWERPC: Machine = Machine(0x1f0);
/// Power PC with floating point support
pub const PM_POWERPCFP: Machine = Machine(0x1f1);
/// MIPS little endian
pub const PM_R4000: Machine = Machine(0x166);
/// Hitachi SH3
pub const PM_SH3: Machine = Machine(0x1a2);
/// Hitachi SH3 DSP
pub const PM_SH3DSP: Machine = Machine(0x1a3);
/// Hitachi SH4
pub const PM_SH4: Machine = Machine(0x1a6);
/// Hitachi SH5
pub const PM_SH5: Machine = Machine(0x1a8);
/// ARM or Thumb ("interworking")
pub const PM_THUMB: Machine = Machine(0x1c2);
/// MIPS little-endian WCE v2
pub const PM_WCEMIPSSV2: Machine = Machine(0x169);

impl fmt::Debug for Machine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Machine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            PM_UNKNOWN => "invalid",
            PM_AM33 => "Matsushita AM33",
            PM_AMD6 => "x86",
            PM_ARM => "ARM little endian",
            PM_ARMNT => "ARMv7 (or higher) Thumb mode only",
            PM_ARM64 => "ARMv8 in 64-bit mode",
            PM_EBC => "EFI byte code",
            PM_I386 => "Intel 386 or later processors and compatible processors",
            PM_IA64 => "Intel Itanium processor family",
            PM_M32R => "Mitsubishi M32R little endian",
            PM_MIPS16 => "MIPS16",
            PM_MIPSFPU => "MIPS with FPU",
            PM_MIPSFPU16 => "MIPS16 with FPU",
            PM_POWERPC => "Power PC little endian",
            PM_POWERPCFP => "Power PC with floating point support",
            PM_R4000 => "MIPS little endian",
            PM_SH3 => "Hitachi SH3",
            PM_SH3DSP => "Hitachi SH3 DSP",
            PM_SH4 => "Hitachi SH4",
            PM_SH5 => "Hitachi SH5",
            PM_THUMB => "ARM or Thumb (\"interworking\") ",
            PM_WCEMIPSSV2 => "MIPS little-endian WCE v2",
            _ => "unknown",
        };
        write!(f, "{}", str)
    }
}

pub const DOS_HDR_MAG: u16 = 0x5A4D;
pub const PE_HDR_MAG: u32 = 0x00004550;

pub struct FileHeader {
    pub machine: Machine,
    pub num_sections: u16,
    pub create_time: u32,
    pub opt_hdr_size: u16,
    pub characteristics: u16,
}

pub struct OptionalHeader {
    pub magic: Class,
    pub maj_link_ver: u8,
    pub min_link_ver: u8,
    pub code_size: u32,
    pub init_size: u32,
    pub uninit_size: u32,
    pub enter_addr: u32,
    pub base_code: u32,
    pub base_data: u32,
    pub base_img: u64,
    pub align_sec: u32,
    pub align_file: u32,
    pub maj_op_ver: u16,
    pub min_op_ver: u16,
    pub maj_img_ver: u16,
    pub min_img_ver: u16,
    pub maj_sub_ver: u16,
    pub min_sub_ver: u16,
    pub win_ver_val: u32,
    pub img_size: u32,
    pub hdr_size: u32,
    pub chksum: u32,
    pub subsys: u16,
    pub dll_char: u16,
    pub stack_rsrv_size: u64,
    pub stack_commit_size: u64,
    pub heap_rsrv_size: u64,
    pub heap_commit_size: u64,
    pub loader_flags: u32,
    pub num_rva: u32,
}

pub struct SectionHeader {
    pub name: ::std::ffi::CString,
    pub virt_size: u32,
    pub virt_addr: u64,
    pub data_size: u32,
    pub raw_ptr: u32,
    pub reloc_ptr: u32,
    pub line_no_ptr: u32,
    pub num_relocs: u16,
    pub num_line_no: u16,
    pub characteristics: u32,
}

impl SectionHeader {
    pub fn address(&self) -> u64 {
        self.virt_addr as u64
    }
}
