pub mod file;

pub use elf::file::File;

/// Length of ELF identification fields
pub const EI_NIDENT: usize = 16;
/// First few bytes of ELF identification
pub static ELFMAG: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];
/// Location in ELF identification of class field
pub const EI_CLASS: usize = 4;
/// Location in ELF identification of data field
pub const EI_DATA: usize = 5;
/// Location in ELF identification of version field
pub const EI_VERSION: usize = 6;
/// Location in ELF identification of OS ABI field
pub const EI_OSABI: usize = 7;
/// Location in ELF identification of ABI version field
pub const EI_ABIVERSION: usize = 8;

pub struct Class(pub u8);
pub const ELFCLASSNONE: Class = Class(0);
pub const ELFCLASS32: Class = Class(1);
pub const ELFCLASS64: Class = Class(2);

pub struct Data(pub u8);
/// Invalid ELF data format
pub const ELFDATANONE: Data = Data(0);
/// Little-endian ELF data format
pub const ELFDATA2LSB: Data = Data(1);
/// Big-endian ELF data format
pub const ELFDATA2MSB: Data = Data(2);

pub struct Version(pub u32);

pub struct OsAbi(pub u8);

pub struct Machine(pub u16);

pub struct Type(pub u16);

pub struct SectionType(pub u32);

pub struct SectionFlag(pub u64);

pub struct FileHeader {
    pub class: Class,
    pub data: Data,
    pub version: Version,
    pub os_abi: OsAbi,
    pub abi_version: u8,
    pub elf_type: Type,
    pub machine: Machine,
    pub entrypoint: u64,
}

pub struct SectionHeader {
    pub name: String,
    pub shtype: SectionType,
    pub flags: SectionFlag,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
}
