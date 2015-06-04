pub mod file;

pub use pe::file::File;
use std::fmt;

pub const DOS_HDR_MAG: u16 = 0x5A4D;
pub const PE_HDR_MAG: u32 = 0x00004550;

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

pub struct Machine(pub u16);

impl fmt::Debug for Machine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

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
    pub base_img: u32,
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
    pub stack_rsrv_size: u32,
    pub stack_commit_size: u32,
    pub heap_rsrv_size: u32,
    pub heap_commit_size: u32,
    pub loader_flags: u32,
    pub num_rva: u32,
}

pub struct SectionHeader {
    pub name: ::std::ffi::CString,
    pub virt_size: u32,
    pub virt_addr: u32,
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
