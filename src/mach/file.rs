use std::io::prelude::*;
use std::io;
use std::error;
use std::collections::HashMap;
use mach::types;
use byteorder;
use byteorder::ReadBytesExt;
use {Error, Section, Object};

macro_rules! read_u8 {
    ($io:ident) => {
        $io.read_u8()
    };
}

macro_rules! read_u16 {
    ($data:ident, $io:ident) => (
        match $data {
            types::MACH_DATA_2LSB => { $io.read_u16::<byteorder::LittleEndian>() },
            types::MACH_DATA_2MSB => { $io.read_u16::<byteorder::BigEndian>()},
            _ => { try!(Err(Error::from("invalid endianness"))) },
        }
    );
}
macro_rules! read_u32 {
    ($data:ident, $io:ident) => (
        match $data {
            types::MACH_DATA_2LSB => { $io.read_u32::<byteorder::LittleEndian>() },
            types::MACH_DATA_2MSB => { $io.read_u32::<byteorder::BigEndian>()},
            _ => { try!(Err(Error::from("invalid endianness"))) },
        }
    );
}
macro_rules! read_i32 {
    ($data:ident, $io:ident) => (
        match $data {
            types::MACH_DATA_2LSB => { $io.read_i32::<byteorder::LittleEndian>() },
            types::MACH_DATA_2MSB => { $io.read_i32::<byteorder::BigEndian>()},
            _ => { try!(Err(Error::from("invalid endianness"))) },
        }
    );
}
macro_rules! read_i64 {
    ($data:ident, $io:ident) => (
        match $data {
            types::MACH_DATA_2LSB => { $io.read_i64::<byteorder::LittleEndian>() },
            types::MACH_DATA_2MSB => { $io.read_i64::<byteorder::BigEndian>()},
            _ => { try!(Err(Error::from("invalid endianness"))) },
        }
    );
}
macro_rules! read_u64 {
    ($data:ident, $io:ident) => (
        match $data {
            types::MACH_DATA_2LSB => { $io.read_u64::<byteorder::LittleEndian>() },
            types::MACH_DATA_2MSB => { $io.read_u64::<byteorder::BigEndian>()},
            _ => { try!(Err(Error::from("invalid endianness"))) },
        }
    );
}

pub struct File {
    hdr: types::FileHeader,
    cmds: Vec<types::LoadCommand>,
    sections: HashMap<String, Section>,
}

impl File {
    #[allow(unused_variables,unused_assignments)]
    pub fn parse<R: io::Read + io::Seek>(r: &mut R) -> Result<File, Box<error::Error>> {
        try!(r.seek(io::SeekFrom::Start(0)));
        let ident: u64 = 0;
        let mut data = types::Data(2);

        let ident = try!(read_u32!(data, r));
        let magic = ident;

        let mut class = types::Class(0);

        match magic {
            types::MACH_HDR_MAG => {
                data = types::Data(2);
                class = types::Class(1);
            },
            types::MACH_HDR_CIG => {
                data = types::Data(1);
                class = types::Class(1);
            },
            types::MACH64_HDR_MAG => {
                data = types::Data(2);
                class = types::Class(2);
            },
            types::MACH64_HDR_CIG => {
                data = types::Data(1);
                class = types::Class(2);
            },
            _ => try!(Err(Error::from("invalid magic number"))),
        }

        let cputype = types::Machine(try!(read_i32!(data, r)));

        let cpu_subtype = try!(read_u32!(data, r)) ^ 0x80000000;
        let file_type = try!(read_u32!(data, r));
        let ncmds = try!(read_u32!(data, r));
        let sizeof_cmds = try!(read_u32!(data, r));
        let flags = try!(read_u32!(data, r));
        try!(read_u32!(data, r));

        let mut cmds = Vec::new();
        let mut sections = HashMap::new();

        let mut cur_point = 0;
        for _ in 0..ncmds {
            let cmd = try!(read_u32!(data, r));
            let size = try!(read_u32!(data, r));
            cur_point += 8;
            if cmd == 0x19 {
                //Read LC_SECTION
                let mut name_buf = [0u8; 16];
                try!(r.read(&mut name_buf));
                cur_point += 16;
                let mut seg_name = String::from_utf8(name_buf.to_vec()).unwrap();
                seg_name = String::from(seg_name.trim_matches('\0'));
                if seg_name != "__PAGEZERO" {
                    let mut i = 0;
                    let vm_addr = try!(read_u64!(data, r));
                    let vm_size = try!(read_u64!(data, r));
                    let file_off = try!(read_u64!(data, r));
                    let filesize = try!(read_u64!(data, r));
                    let maxprot = try!(read_i32!(data, r));
                    let initprot = try!(read_i32!(data, r));
                    let nsects = try!(read_u32!(data, r));
                    let seg_flags = try!(read_u32!(data, r));
                    cur_point += 48;
                    while i < nsects {
                        //Read Section
                        try!(r.read(&mut name_buf));
                        let mut sect_name = String::from_utf8(name_buf.to_vec()).unwrap();
                        sect_name = String::from(sect_name.trim_matches('\0'));
                        try!(r.read(&mut name_buf));
                        cur_point += 32;
                        let mut sect_seg_name = String::from_utf8(name_buf.to_vec()).unwrap();
                        sect_seg_name = String::from(sect_seg_name.trim_matches('\0'));

                        let addr = try!(read_u64!(data, r));
                        let size = try!(read_u64!(data, r));
                        let offset = try!(read_u32!(data, r));
                        let align = try!(read_u32!(data, r));
                        let reloff = try!(read_u32!(data, r));
                        let nreloc = try!(read_u32!(data, r));
                        let flags = try!(read_u32!(data, r));

                        let _ = try!(read_u64!(data, r));
                        let _ = try!(read_u32!(data, r));

                        cur_point += 48;

                        let t_sect = Section {
                            name: sect_name,
                            addr: addr,
                            offset: offset as u64,
                            size: size,
                            data: Vec::new(),
                        };
                        sections.insert(t_sect.name.clone(), t_sect);
                        i += 1;
                    }
                }
            }
            try!(r.seek(io::SeekFrom::Current((size - cur_point) as i64)));
            cur_point = 0;
            let t_cmd = types::LoadCommand {
                cmd: cmd,
                size: size,
            };
            cmds.push(t_cmd);
        }

        let t_size = sections.get("__text").unwrap().size;
        let mut data_buf = Vec::with_capacity(t_size as usize);
        unsafe { data_buf.set_len(t_size as usize); }
        try!(r.seek(io::SeekFrom::Start(sections.get("__text").unwrap().offset as u64)));
        try!(r.read(&mut data_buf));
        sections.get_mut("__text").unwrap().data = data_buf;

        let x = File {
            hdr: types::FileHeader {
                magic: magic,
                cpu_type: cputype,
                cpu_subtype: cpu_subtype,
                file_type: file_type,
                ncmds: ncmds,
                sizeof_cmds: sizeof_cmds,
                flags: flags,
                data: data,
            },
            cmds: cmds,
            sections: sections,
        };
        Ok(x)
    }
    pub fn sections(&self) -> &HashMap<String, Section> {
        &self.sections
    }
}

impl Object for File {
    fn arch(&self) -> ::Arch {
        let endian = match self.hdr.data {
            types::MACH_DATA_2LSB => ::Endianness::Little,
            types::MACH_DATA_2MSB => ::Endianness::Big,
            _ => return ::Arch::Unknown,
        };
        match self.hdr.cpu_type {
            types::PM_I386 => ::Arch::X86(::Width::W32),
            types::PM_X86_64 => ::Arch::X86(::Width::W64),
            types::PM_POWERPC => ::Arch::PPC(::Width::W32, endian),
            types::PM_POWERPC64 => ::Arch::PPC(::Width::W64, endian),
            _ => return ::Arch::Unknown,
        }
    }
    fn get_section(&self, name: &str) -> Option<&Section> {
        let mut fmt_name = String::from(name.trim_matches('.'));
        fmt_name = String::from("__") + &fmt_name;
        self.sections.get(fmt_name.as_str())
    }
}
