use std::fmt;
use libc::types::os::arch::c95::c_ulong;

pub struct LoadCommand {
    pub cmd: u32,
    pub size: u32,
}

pub struct FileHeader {
    pub magic: u32,
    pub cpu_type: Machine,
    pub cpu_subtype: u32,
    pub file_type: u32,
    pub ncmds: u32,
    pub sizeof_cmds: u32,
    pub flags: u32,
    pub data: Data,
}

#[derive(Debug)]
pub struct SectionHeader {
    pub sect_name: String,
    pub seg_name: String,
    pub addr: c_ulong,
    pub size: c_ulong,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
}

impl SectionHeader {
    pub fn address(&self) -> u64 {
        self.addr as u64
    }
}

pub const NIDENT: usize = 4;

pub const MACH_HDR_MAG: u32 = 0xFEEDFACE;
pub const MACH64_HDR_MAG: u32 = 0xFEEDFACF;
pub const MACH_HDR_CIG: u32 = 0xCEFAEDFE;
pub const MACH64_HDR_CIG: u32 = 0xCFFAEDFE;

pub struct Class(pub u8);
pub const MACH_CLASS_NONE: Class = Class(0);
pub const MACH_CLASS_32: Class = Class(1);
pub const MACH_CLASS_64: Class = Class(2);

impl fmt::Debug for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            MACH_CLASS_NONE => "invalid",
            MACH_CLASS_32 => "32-bit",
            MACH_CLASS_64 => "64-bit",
            _ => "unknown",
        };
        write!(f, "{}", str)
    }
}

pub struct Data(pub u8);
pub const MACH_DATA_NONE: Data = Data(0);
pub const MACH_DATA_2LSB: Data = Data(1);
pub const MACH_DATA_2MSB: Data = Data(2);

impl fmt::Debug for Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            MACH_DATA_NONE => "invalid",
            MACH_DATA_2LSB => "2's complement, little endian",
            MACH_DATA_2MSB => "2's complement, big endian",
            _ => "unknown",
        };
        write!(f, "{}", str)
    }
}

pub const ABI64: i32 = 0x01000000;

pub struct Machine(pub i32);
pub const PM_ANY: Machine = Machine(-1);
pub const PM_VAX: Machine = Machine(1);
pub const PM_MC680X0: Machine = Machine(6);
pub const PM_X86: Machine = Machine(7);
pub const PM_I386: Machine = PM_X86;
pub const PM_X86_64: Machine = Machine(7 | ABI64);
pub const PM_MC98000: Machine = Machine(10);
pub const PM_HPPA: Machine = Machine(11);
pub const PM_MC88000: Machine = Machine(13);
pub const PM_SPARC: Machine = Machine(14);
pub const PM_I860: Machine = Machine(15);
pub const PM_POWERPC: Machine = Machine(18);
pub const PM_POWERPC64: Machine = Machine(18 | ABI64);

impl fmt::Debug for Machine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}
