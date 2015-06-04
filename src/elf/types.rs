use std::fmt;

/// Length of ELF identification fields (platform-independent)
pub const EI_NIDENT: usize = 16;
/// First few bytes of ELF identification ('\177ELF')
pub static ELFMAG: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];
/// File class byte index
pub const EI_CLASS: usize = 4;
/// Data encoding byte index
pub const EI_DATA: usize = 5;
/// File version byte index
pub const EI_VERSION: usize = 6;
/// OS ABI identification
pub const EI_OSABI: usize = 7;
/// ABI version
pub const EI_ABIVERSION: usize = 8;

/// ELF file class (32-bit vs 64-bit)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Class(pub u8);
/// Invalid class
pub const ELFCLASSNONE: Class = Class(0);
/// 32-bit objects
pub const ELFCLASS32: Class = Class(1);
/// 64-bit objects
pub const ELFCLASS64: Class = Class(2);

impl fmt::Debug for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            ELFCLASSNONE => "invalid",
            ELFCLASS32 => "32-bit",
            ELFCLASS64 => "64-bit",
            _ => "unknown",
        };
        write!(f, "{}", str)
    }
}

/// ELF file data format (endianness)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Data(pub u8);
/// Invalid data encoding
pub const ELFDATANONE: Data = Data(0);
/// 2's complement, little endian
pub const ELFDATA2LSB: Data = Data(1);
/// 2's complement, big endian
pub const ELFDATA2MSB: Data = Data(2);

impl fmt::Debug for Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            ELFDATANONE => "invalid",
            ELFDATA2LSB => "2's complement, little endian",
            ELFDATA2MSB => "2's complement, big endian",
            _ => "unknown",
        };
        write!(f, "{}", str)
    }
}

/// ELF file version information
///
/// (found both in e_ident and e_version
///
/// "Should always be EV_CURRENT"
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Version(pub u32);
/// Invalid ELF version
pub const EV_NONE: Version = Version(0);
/// Current version
pub const EV_CURRENT: Version = Version(1);

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            EV_NONE => "invalid",
            EV_CURRENT => "1 (current)",
            _ => "unknown",
        };
        write!(f, "{}", str)
    }
}

/// ELF file OS ABI
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OsAbi(pub u8);
/// Default is UNIX System V
pub const ELFOSABI_NONE: OsAbi = OsAbi(0);
/// UNIX System V ABI
pub const ELFOSABI_SYSV: OsAbi = OsAbi(0);
/// HP-UX
pub const ELFOSABI_HPUX: OsAbi = OsAbi(1);
/// NetBSD
pub const ELFOSABI_NETBSD: OsAbi = OsAbi(2);
/// Linux (GNU extensions)
pub const ELFOSABI_LINUX: OsAbi = OsAbi(3);
/// GNU extensions
pub const ELFOSABI_GNU: OsAbi = OsAbi(3);
/// Solaris
pub const ELFOSABI_SOLARIS: OsAbi = OsAbi(6);
/// AIX
pub const ELFOSABI_AIX: OsAbi = OsAbi(7);
/// SGI IRIX
pub const ELFOSABI_IRIX: OsAbi = OsAbi(8);
/// FreeBSD
pub const ELFOSABI_FREEBSD: OsAbi = OsAbi(9);
/// Compaq Tru64 UNIX
pub const ELFOSABI_TRU64: OsAbi = OsAbi(10);
/// Novell Modesto
pub const ELFOSABI_MODESTO: OsAbi = OsAbi(11);
/// OpenBSD
pub const ELFOSABI_OPENBSD: OsAbi = OsAbi(12);
/// ARM EABI
pub const ELFOSABI_ARM_AEABI: OsAbi = OsAbi(64);
/// ARM
pub const ELFOSABI_ARM: OsAbi = OsAbi(97);
/// Standalone (embedded) application
pub const ELFOSABI_STANDALONE: OsAbi = OsAbi(255);

impl fmt::Debug for OsAbi {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for OsAbi {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            ELFOSABI_NONE => "UNIX System V",
            ELFOSABI_HPUX => "HP-UX",
            ELFOSABI_NETBSD => "NetBSD",
            ELFOSABI_LINUX => "Linux (with GNU extensions)",
            ELFOSABI_SOLARIS => "Solaris",
            ELFOSABI_AIX => "AIX",
            ELFOSABI_IRIX => "SGI IRIX",
            ELFOSABI_FREEBSD => "FreeBSD",
            ELFOSABI_TRU64 => "Compaq TRU64 UNIX",
            ELFOSABI_MODESTO => "Novell Modesto",
            ELFOSABI_OPENBSD => "OpenBSD",
            ELFOSABI_ARM_AEABI => "ARM EABI",
            ELFOSABI_ARM => "ARM",
            ELFOSABI_STANDALONE => "Standalone",
            _ => "unknown",
        };
        write!(f, "{}", str)
    }
}

/// ELF file machine architecture
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Machine(pub u16);
/// Invalid machine architecture
pub const EM_NONE: Machine = Machine(0);
/// AT&T WE 32100
pub const EM_M32: Machine = Machine(1);
/// SUN SPARC
pub const EM_SPARC: Machine = Machine(2);
/// Intel 80386
pub const EM_386: Machine = Machine(3);
/// Motorola m68k family
pub const EM_68K: Machine = Machine(4);
/// Motorola m88k family
pub const EM_88K: Machine = Machine(5);
/// Intel 80860
pub const EM_860: Machine = Machine(7);
/// MIPS R3000 big-endian
pub const EM_MIPS: Machine = Machine(8);
/// IBM System/370
pub const EM_S370: Machine = Machine(9);
/// MIPS R3000 little-endian
pub const EM_MIPS_RS3_LE: Machine = Machine(10);
/// HPPA
pub const EM_PARISC: Machine = Machine(15);
/// Fujitsu VPP5000
pub const EM_VPP500: Machine = Machine(17);
/// Sun's "v8plus"
pub const EM_SPARC32PLUS: Machine = Machine(18);
/// Intel 80960
pub const EM_960: Machine = Machine(19);
/// PowerPC
pub const EM_PPC: Machine = Machine(20);
/// PowerPC 64-bit
pub const EM_PPC64: Machine = Machine(21);
/// IBM S390
pub const EM_S390: Machine = Machine(22);
/// NEC V800
pub const EM_V800: Machine = Machine(36);
/// Fujitsu FR20
pub const EM_FR20: Machine = Machine(37);
/// TRW RH-32
pub const EM_RH32: Machine = Machine(38);
/// Motorola RCE
pub const EM_RCE: Machine = Machine(39);
/// ARM
pub const EM_ARM: Machine = Machine(40);
/// Digital Alpha
pub const EM_FAKE_ALPHA: Machine = Machine(41);
/// Hitachi SH
pub const EM_SH: Machine = Machine(42);
/// SPARC v9 64-bit
pub const EM_SPARCV9: Machine = Machine(43);
/// Siemens Tricore
pub const EM_TRICORE: Machine = Machine(44);
/// Argonaut RISC Core
pub const EM_ARC: Machine = Machine(45);
/// Hitachi H8/300
pub const EM_H8_300: Machine = Machine(46);
/// Hitachi H8/300H
pub const EM_H8_300H: Machine = Machine(47);
/// Hitachi H8S
pub const EM_H8S: Machine = Machine(48);
/// Hitachi H8/500
pub const EM_H8_500: Machine = Machine(49);
/// Intel Merced
pub const EM_IA_64: Machine = Machine(50);
/// Stanford MIPS-X
pub const EM_MIPS_X: Machine = Machine(51);
/// Motorola Coldfire
pub const EM_COLDFIRE: Machine = Machine(52);
/// Motorola M68HC12
pub const EM_68HC12: Machine = Machine(53);
/// Fujitsu MMA Multimedia Accelerator
pub const EM_MMA: Machine = Machine(54);
/// Siemens PCP
pub const EM_PCP: Machine = Machine(55);
/// Sony nCPU embedded RISC
pub const EM_NCPU: Machine = Machine(56);
/// Denso NDR1 microprocessor
pub const EM_NDR1: Machine = Machine(57);
/// Motorola Star*Core processor
pub const EM_STARCORE: Machine = Machine(58);
/// Toyota ME16 processor
pub const EM_ME16: Machine = Machine(59);
/// STMicroelectronics ST100 processor
pub const EM_ST100: Machine = Machine(60);
/// Advanced Logic Corp. Tinyj emb.fam
pub const EM_TINYJ: Machine = Machine(61);
/// AMD x86-64 architecture
pub const EM_X86_64: Machine = Machine(62);
/// Sony DSP processor
pub const EM_PDSP: Machine = Machine(63);
/// Siemens FX66 microcontroller
pub const EM_FX66: Machine = Machine(66);
/// STMicroelectronics ST9+ 8/16 mc
pub const EM_ST9PLUS: Machine = Machine(67);
/// STMicroelectronics ST7 8 bit mc
pub const EM_ST7: Machine = Machine(68);
/// Motorola M68HC16 microcontroller
pub const EM_68HC16: Machine = Machine(69);
/// Motorola M68HC11 microcontroller
pub const EM_68HC11: Machine = Machine(70);
/// Motorola M68HC08 microcontroller
pub const EM_68HC08: Machine = Machine(71);
/// Motorola M68HC05 microcontroller
pub const EM_68HC05: Machine = Machine(72);
/// Silicon Graphics SVx
pub const EM_SVX: Machine = Machine(73);
/// STMicroelectronics ST19 8 bit mc
pub const EM_ST19: Machine = Machine(74);
/// Digital VAX
pub const EM_VAX: Machine = Machine(75);
/// Axis Communications 32-bit embedded processor
pub const EM_CRIS: Machine = Machine(76);
/// Infineon Technologies 32-bit embedded processor
pub const EM_JAVELIN: Machine = Machine(77);
/// Element 14 64-bit DSP Processor
pub const EM_FIREPATH: Machine = Machine(78);
/// LSI Logic 16-bit DSP Processor
pub const EM_ZSP: Machine = Machine(79);
/// Donald Knuth's educational 64-bit processor
pub const EM_MMIX: Machine = Machine(80);
/// Harvard University machine-independent object files
pub const EM_HUANY: Machine = Machine(81);
/// SiTera Prism
pub const EM_PRISM: Machine = Machine(82);
/// Atmel AVR 8-bit microcontroller
pub const EM_AVR: Machine = Machine(83);
/// Fujitsu FR30
pub const EM_FR30: Machine = Machine(84);
/// Mitsubishi D10V
pub const EM_D10V: Machine = Machine(85);
/// Mitsubishi D30V
pub const EM_D30V: Machine = Machine(86);
/// NEC v850
pub const EM_V850: Machine = Machine(87);
/// Mitsubishi M32R
pub const EM_M32R: Machine = Machine(88);
/// Matsushita MN10300
pub const EM_MN10300: Machine = Machine(89);
/// Matsushita MN10200
pub const EM_MN10200: Machine = Machine(90);
/// picoJava
pub const EM_PJ: Machine = Machine(91);
/// OpenRISC 32-bit embedded processor
pub const EM_OPENRISC: Machine = Machine(92);
/// ARC Cores Tangent-A5
pub const EM_ARC_A5: Machine = Machine(93);
/// Tensilica Xtensa Architecture
pub const EM_XTENSA: Machine = Machine(94);
/// Altera Nios II
pub const EM_ALTERA_NIOS2: Machine = Machine(113);
/// ARM AARCH64
pub const EM_AARCH64: Machine = Machine(183);
/// Tilera TILEPro
pub const EM_TILEPRO: Machine = Machine(188);
/// Xilinx MicroBlaze
pub const EM_MICROBLAZE: Machine = Machine(189);
/// Tilera TILE-Gx
pub const EM_TILEGX: Machine = Machine(191);
/// Alpha
pub const EM_ALPHA: Machine = Machine(0x9026);

impl fmt::Debug for Machine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Machine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            EM_NONE => "invalid",
            EM_M32 => "AT&T WE 32100",
            EM_SPARC => "SUN SPARC",
            EM_386 => "Intel 80386",
            EM_68K => "Motorola m68k family",
            EM_88K => "Motorola m88k family",
            EM_860 => "Intel 80860",
            EM_MIPS => "MIPS R3000 big-endian",
            EM_S370 => "IBM System/370",
            EM_MIPS_RS3_LE => "MIPS R3000 little-endian",
            EM_PARISC => "HPPA",
            EM_VPP500 => "Fujitsu VPP500",
            EM_SPARC32PLUS => "Sun's \"v8plus\"",
            EM_960 => "Intel 80960",
            EM_PPC => "PowerPC",
            EM_PPC64 => "PowerPC 64-bit",
            EM_S390 => "IBM S390",
            EM_V800 => "NEC V800 series",
            EM_FR20 => "Fujitsu FR20",
            EM_RH32 => "TRW RH-32",
            EM_RCE => "Motorola RCE",
            EM_ARM => "ARM",
            EM_FAKE_ALPHA => "Digital Alpha",
            EM_SH => "Hitachi SH",
            EM_SPARCV9 => "SPARC v9 64-bit",
            EM_TRICORE => "Siemens Tricore",
            EM_ARC => "Argonaut RISC Core",
            EM_H8_300 => "Hitachi H8/300",
            EM_H8_300H => "Hitachi H8/300H",
            EM_H8S => "Hitachi H8S",
            EM_H8_500 => "Hitachi H8/500",
            EM_IA_64 => "Intel Merced",
            EM_MIPS_X => "Stanford MIPS-X",
            EM_COLDFIRE => "Motorola Coldfire",
            EM_68HC12 => "Motorola M68HC12",
            EM_MMA => "Fujitsu MMA Multimedia Accelerator",
            EM_PCP => "Siemens PCP",
            EM_NCPU => "Sony nCPU embedded RISC",
            EM_NDR1 => "Denso NDR1 microprocessor",
            EM_STARCORE => "Motorola Star*Core processor",
            EM_ME16 => "Toyota ME16 processor",
            EM_ST100 => "STMicroelectronics ST100 processor",
            EM_TINYJ => "Advanced Logic Corp. Tinyj emb.fam",
            EM_X86_64 => "AMD x86-64 architecture",
            EM_PDSP => "Sony DSP Processor",
            EM_FX66 => "Siemens FX66 microcontroller",
            EM_ST9PLUS => "STMicroelectronics ST9+ 8/16 mc",
            EM_ST7 => "STMicroelectronics ST7 8 bit mc",
            EM_68HC16 => "Motorola MC68HC16 microcontroller",
            EM_68HC11 => "Motorola MC68HC11 microcontroller",
            EM_68HC08 => "Motorola MC68HC08 microcontroller",
            EM_68HC05 => "Motorola MC68HC05 microcontroller",
            EM_SVX => "Silicon Graphics SVx",
            EM_ST19 => "STMicroelectronics ST19 8 bit mc",
            EM_VAX => "Digital VAX",
            EM_CRIS => "Axis Communications 32-bit embedded processor",
            EM_JAVELIN => "Infineon Technologies 32-bit embedded processor",
            EM_FIREPATH => "Element 14 64-bit DSP Processor",
            EM_ZSP => "LSI Logic 16-bit DSP Processor",
            EM_MMIX => "Donald Knuth's educational 64-bit processor",
            EM_HUANY => "Harvard University machine-independent object files",
            EM_PRISM => "SiTera Prism",
            EM_AVR => "Atmel AVR 8-bit microcontroller",
            EM_FR30 => "Fujitsu FR30",
            EM_D10V => "Mitsubishi D10V",
            EM_D30V => "Mitsubishi D30V",
            EM_V850 => "NEC v850",
            EM_M32R => "Mitsubishi M32R",
            EM_MN10300 => "Matsushita MN10300",
            EM_MN10200 => "Matsushita MN10200",
            EM_PJ => "picoJava",
            EM_OPENRISC => "OpenRISC 32-bit embedded processor",
            EM_ARC_A5 => "ARC Cores Tangent-A5",
            EM_XTENSA => "Tensilica Xtensa Architecture",
            EM_ALTERA_NIOS2 => "Altera Nios II",
            EM_AARCH64 => "ARM AARCH64",
            EM_TILEPRO => "Tilera TILEPro",
            EM_MICROBLAZE => "Xilinx MicroBlaze",
            EM_TILEGX => "Tilera TILE-Gx",
            EM_ALPHA => "Alpha",
            _ => "unknown",
        };
        write!(f, "{}", str)
    }
}

/// ELF object file type (object, executable)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Type(pub u16);
/// Invalid file type
pub const ET_NONE: Type = Type(0);
/// Relocatable file
pub const ET_REL: Type = Type(1);
/// Executable file
pub const ET_EXEC: Type = Type(2);
/// Shared object file
pub const ET_DYN: Type = Type(3);
/// Core file
pub const ET_CORE: Type = Type(4);

impl fmt::Debug for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            ET_NONE => "invalid",
            ET_REL => "relocatable",
            ET_EXEC => "executable",
            ET_DYN => "shared object",
            ET_CORE => "core",
            _ => "unknown",
        };
        write!(f, "{}", str)
    }
}

/// ELF section type
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SectionType(pub u32);
/// Unused entry
pub const SHT_NULL: SectionType = SectionType(0);
/// Program data
pub const SHT_PROGBIGS: SectionType = SectionType(1);
/// Symbol table
pub const SHT_SYMTAB: SectionType = SectionType(2);
/// String table
pub const SHT_STRTAB: SectionType = SectionType(3);
/// Relocation entries with addends
pub const SHT_RELA: SectionType = SectionType(4);
/// Symbol hash table
pub const SHT_HASH: SectionType = SectionType(5);
/// Dynamic linking information
pub const SHT_DYNAMIC: SectionType = SectionType(6);
/// Notes
pub const SHT_NOTE: SectionType = SectionType(7);
/// Program space with no data (bss)
pub const SHT_NOBITS: SectionType = SectionType(8);
/// Relocation entries, no addends
pub const SHT_REL: SectionType = SectionType(9);
/// Reserved
pub const SHT_SHLIB: SectionType = SectionType(10);
/// Dynamic linker symbol table
pub const SHT_DYNSYM: SectionType = SectionType(11);
/// Array of constructors
pub const SHT_INIT_ARRAY: SectionType = SectionType(14);
/// Array of destructors
pub const SHT_FINI_ARRAY: SectionType = SectionType(15);
/// Array of pre-constructors
pub const SHT_PREINIT_ARRAY: SectionType = SectionType(16);
/// Section group
pub const SHT_GROUP: SectionType = SectionType(17);
/// Extended section indeces
pub const SHT_SYMTAB_SHNDX: SectionType = SectionType(18);
/// Object attributes
pub const SHT_GNU_ATTRIBUTES: SectionType = SectionType(0x6ffffff5);
/// GNU-style hash table
pub const SHT_GNU_HASH: SectionType = SectionType(0x6ffffff6);
/// Prelink library list
pub const SHT_GNU_LIBLIST: SectionType = SectionType(0x6ffffff7);
/// Checksum for DSO content
pub const SHT_CHECKSUM: SectionType = SectionType(0x6ffffff8);
/// Version definition section
pub const SHT_GNU_VERDEF: SectionType = SectionType(0x6ffffffd);
/// Version needs section
pub const SHT_GNU_VERNEED: SectionType = SectionType(0x6ffffffe);
/// Version symbol table
pub const SHT_GNU_VERSYM: SectionType = SectionType(0x6fffffff);

impl fmt::Debug for SectionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for SectionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            SHT_NULL => "SHT_NULL",
            SHT_PROGBIGS => "SHT_PROGBITS",
            SHT_SYMTAB => "SHT_SYMTAB",
            SHT_STRTAB => "SHT_STRTAB",
            SHT_RELA => "SHT_RELA",
            SHT_HASH => "SHT_HASH",
            SHT_DYNAMIC => "SHT_DYNAMIC",
            SHT_NOTE => "SHT_NOTE",
            SHT_NOBITS => "SHT_NOBITS",
            SHT_REL => "SHT_REL",
            SHT_SHLIB => "SHT_SHLIB",
            SHT_DYNSYM => "SHT_DYNSYM",
            SHT_INIT_ARRAY => "SHT_INIT_ARRAY",
            SHT_FINI_ARRAY => "SHT_FINI_ARRAY",
            SHT_PREINIT_ARRAY => "SHT_PREINIT_ARRAY",
            SHT_GROUP => "SHT_GROUP",
            SHT_SYMTAB_SHNDX => "SHT_SYMTAB_SHNDX",
            SHT_GNU_ATTRIBUTES => "SHT_GNU_ATTRIBUTES",
            SHT_GNU_HASH => "SHT_GNU_HASH",
            SHT_GNU_LIBLIST => "SHT_GNU_LIBLIST",
            SHT_CHECKSUM => "SHT_CHECKSUM",
            SHT_GNU_VERDEF => "SHT_GNU_VERDEF",
            SHT_GNU_VERNEED => "SHT_GNU_VERNEED",
            SHT_GNU_VERSYM => "SHT_GNU_VERSYM",
            _ => "unknown",
        };
        write!(f, "{}", str)
    }
}


/// ELF section flag
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SectionFlag(pub u64);
/// Writable
pub const SHF_WRITE: SectionFlag = SectionFlag(1 << 0);
/// Occupies memory during execution
pub const SHF_ALLOC: SectionFlag = SectionFlag(1 << 1);
/// Executable
pub const SHF_EXECINSTR: SectionFlag = SectionFlag(1 << 2);
/// Might be merged
pub const SHF_MERGE: SectionFlag = SectionFlag(1 << 4);
/// Contains nul-terminated strings
pub const SHF_STRINGS: SectionFlag = SectionFlag(1 << 5);
/// `sh_info' contains SHT index
pub const SHF_INFO_LINK: SectionFlag = SectionFlag(1 << 6);
/// Preserve order after combining
pub const SHF_LINK_ORDER: SectionFlag = SectionFlag(1 << 7);
/// Non-standard OS specific handling required
pub const SHF_OS_NONCONFORMING: SectionFlag = SectionFlag(1 << 8);
/// Section is member of a group
pub const SHF_GROUP: SectionFlag = SectionFlag(1 << 9);
/// Section holds thread-local data
pub const SHF_TLS: SectionFlag = SectionFlag(1 << 10);
/// Special ordering requirement (Solaris)
pub const SHF_ORDERED: SectionFlag = SectionFlag(1 << 30);
/// Section is excluded unless referenced or allocared (Solaris)
pub const SHF_EXCLUDE: SectionFlag = SectionFlag(1 << 31);

impl fmt::Debug for SectionFlag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}
impl fmt::Display for SectionFlag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}
/// ELF program header type
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProgType(pub u32);
/// Unused entry
pub const PT_NULL: ProgType = ProgType(0);
/// Loadable program segment
pub const PT_LOAD: ProgType = ProgType(1);
/// Dynamic linking information
pub const PT_DYNAMIC: ProgType = ProgType(2);
/// Program interpreter
pub const PT_INTERP: ProgType = ProgType(3);
/// Auxiliary information
pub const PT_NOTE: ProgType = ProgType(4);
/// Reserved
pub const PT_SHLIB: ProgType = ProgType(5);
/// Entry for header table itself
pub const PT_PHDR: ProgType = ProgType(6);
/// Thread-local storage segment
pub const PT_TLS: ProgType = ProgType(7);
/// GCC .eh_frame_hdr segment
pub const PT_GNU_EH_FRAME: ProgType = ProgType(0x6474e550);
/// Indicates stack executability
pub const PT_GNU_STACK: ProgType = ProgType(0x6474e551);
/// Read-only after relocation
pub const PT_GNU_RELRD: ProgType = ProgType(0x6474e552);
/// Sun Specific segment
pub const PT_SUNWBSS: ProgType = ProgType(0x6ffffffa);
/// Stack segment
pub const PT_SUNWSTACK: ProgType = ProgType(0x6ffffffb);

impl fmt::Debug for ProgType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}
impl fmt::Display for ProgType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            PT_NULL => "PT_NULL",
            PT_LOAD => "PT_LOAD",
            PT_DYNAMIC => "PT_DYNAMIC",
            PT_INTERP => "PT_INTERP",
            PT_NOTE => "PT_NOTE",
            PT_SHLIB => "PT_SHLIB",
            PT_PHDR => "PT_PHDR",
            PT_TLS => "PT_TLS",
            PT_GNU_EH_FRAME => "PT_GNU_EH_FRAME",
            PT_GNU_STACK => "PT_GNU_STACK",
            PT_GNU_RELRD => "PT_GNU_RELRD",
            PT_SUNWBSS => "PT_SUNWBSS",
            PT_SUNWSTACK => "PT_SUNWSTACK",
            _ => "unknown",
        };
        write!(f, "{}", str)
    }
}

/// ELF program header flags
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProgFlag(pub u32);
/// Segment is executable
pub const PF_X: ProgFlag = ProgFlag(1 << 0);
/// Segment is writable
pub const PF_W: ProgFlag = ProgFlag(1 << 1);
/// Segment is readable
pub const PF_R: ProgFlag = ProgFlag(1 << 2);

impl fmt::Debug for ProgFlag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for ProgFlag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.0 & PF_R.0 != 0 {
            try!(write!(f, "R"));
        } else {
            try!(write!(f, " "));
        }
        if self.0 & PF_W.0 != 0 {
            try!(write!(f, "W"));
        } else {
            try!(write!(f, " "));
        }
        if self.0 & PF_X.0 != 0 {
            write!(f, "E")
        } else {
            write!(f, " ")
        }
    }
}

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

impl fmt::Display for FileHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "ELF header for {} {} ELF {} for {} {}", self.class, self.data, self.elf_type, self.os_abi, self.machine)
    }
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
impl fmt::Display for SectionHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Section '{}': type: {} flags: {} addr: {:#010x} offset: {:#06x} size: {:#06x} link: {} info: {:#x} addralign: {} entsize: {}",
               self.name, self.shtype, self.flags, self.addr, self.offset, self.size, self.link, self.info, self.addralign, self.entsize)
    }
}

pub struct ProgramHeader {
    pub progtype: ProgType,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub flags: ProgFlag,
    pub align: u64,
}
