use std::io::prelude::*;
use std::io;
use std::ffi;
use std::fmt;
use std::error;
use byteorder;
use byteorder::ReadBytesExt;
use pe::types;
use std::collections::HashMap;
use {Error, Object, Section};

macro_rules! read_u8 {
    ($io:ident) => (
        $io.read_u8()
    );
}

macro_rules! read_u16 {
    ($io:ident) => (
        $io.read_u16::<byteorder::LittleEndian>()
    );
}

macro_rules! read_u32 {
    ($io:ident) => (
        $io.read_u32::<byteorder::LittleEndian>()
    );
}

macro_rules! read_u64 {
    ($io:ident) => (
        $io.read_u64::<byteorder::LittleEndian>()
    );
}

pub struct File {
    pub file_hdr: types::FileHeader,
    pub opt_hdr: types::OptionalHeader,
    pub sections: HashMap<String, Section>,
}

impl File {
    #[allow(unused_variables,unused_assignments)]
    pub fn parse<R: io::Read + io::Seek>(r: &mut R) -> Result<File, Box<error::Error>> {
        try!(r.seek(io::SeekFrom::Start(0)));
        let dossig = try!(read_u16!(r));

        if dossig != types::DOS_HDR_MAG {
            try!(Err(Error::from("invalid DOS signature")));
        }

        try!(r.seek(io::SeekFrom::Start(0x3c)));

        let foff = try!(read_u32!(r));

        try!(r.seek(io::SeekFrom::Start(foff as u64)));

        let pesig = try!(read_u32!(r));

        if pesig != types::PE_HDR_MAG {
            try!(Err(Error::from("invalid PE signature")));
        }

        let machine = types::Machine(try!(read_u16!(r)));
        let num_sections = try!(read_u16!(r));
        let create_time = try!(read_u32!(r));
        let sym_tab_ptr = try!(read_u32!(r));
        let num_sym = try!(read_u32!(r));
        let opt_hdr_size = try!(read_u16!(r));
        let characteristics = try!(read_u16!(r));

        if opt_hdr_size == 0 {
            try!(Err(Error::from("optional header missing")));
        }

        let magic = types::Class(try!(read_u16!(r)));
        let maj_link_ver = try!(read_u8!(r));
        let min_link_ver = try!(read_u8!(r));
        let code_size = try!(read_u32!(r));
        let init_size = try!(read_u32!(r));
        let uninit_size = try!(read_u32!(r));
        let enter_addr = try!(read_u32!(r));
        let base_code = try!(read_u32!(r));
        let base_data = {
            if magic == types::PECLASS64 {
                0
            } else {
                try!(read_u32!(r))
            }
        };
        let base_img = {
            if magic == types::PECLASS64 {
                try!(read_u64!(r))
            } else {
                try!(read_u32!(r)) as u64
            }
        };
        let align_sec = try!(read_u32!(r));
        let align_file = try!(read_u32!(r));
        let maj_op_ver = try!(read_u16!(r));
        let min_op_ver = try!(read_u16!(r));
        let maj_img_ver = try!(read_u16!(r));
        let min_img_ver = try!(read_u16!(r));
        let maj_sub_ver = try!(read_u16!(r));
        let min_sub_ver = try!(read_u16!(r));
        let win_ver_val = try!(read_u32!(r));
        let img_size = try!(read_u32!(r));
        let hdr_size = try!(read_u32!(r));
        let chksum = try!(read_u32!(r));
        let subsys = try!(read_u16!(r));
        let dll_char = try!(read_u16!(r));
        let stack_rsrv_size = {
            if magic == types::PECLASS64 {
                try!(read_u64!(r))
            } else {
                try!(read_u32!(r)) as u64
            }
        };
        let stack_commit_size = {
            if magic == types::PECLASS64 {
                try!(read_u64!(r))
            } else {
                try!(read_u32!(r)) as u64
            }
        };
        let heap_rsrv_size = {
            if magic == types::PECLASS64 {
                try!(read_u64!(r))
            } else {
                try!(read_u32!(r)) as u64
            }
        };
        let heap_commit_size = {
            if magic == types::PECLASS64 {
                try!(read_u64!(r))
            } else {
                try!(read_u32!(r)) as u64
            }
        };
        let loader_flags = try!(read_u32!(r));
        let num_rva = try!(read_u32!(r));

        try!(r.seek(io::SeekFrom::Start((foff as u64+opt_hdr_size as u64+0x18))));

        let mut sections_lst = Vec::new();
        let mut sections = HashMap::new();

        for _ in 0..num_sections {
            let mut name = [0u8; 8];

            try!(r.read(&mut name));

            let mut name_str = name.as_ref();

            if name.contains(&0) {
                name_str = &name_str[..name.iter().position(|x| x == &0).unwrap()]
            }

            let virt_size = try!(read_u32!(r));
            let virt_addr = try!(read_u32!(r)) as u64 + base_img;
            let data_size = try!(read_u32!(r));
            let raw_ptr = try!(read_u32!(r));
            let reloc_ptr = try!(read_u32!(r));
            let line_no_ptr = try!(read_u32!(r));
            let num_relocs = try!(read_u16!(r));
            let num_line_no = try!(read_u16!(r));
            let characteristics = try!(read_u32!(r));
            let name =  ffi::CString::new(name_str).unwrap();

            sections_lst.push(types::SectionHeader {
                    name: name,
                    virt_size: virt_size,
                    virt_addr: virt_addr,
                    data_size: data_size,
                    raw_ptr: raw_ptr,
                    reloc_ptr: reloc_ptr,
                    line_no_ptr: line_no_ptr,
                    num_relocs: num_relocs,
                    num_line_no: num_line_no,
                    characteristics: characteristics,
            });
        }

        for shdr in sections_lst.into_iter() {
            try!(r.seek(io::SeekFrom::Start(shdr.raw_ptr as u64)));
            let data: Vec<u8> = io::Read::by_ref(r).bytes().map(|x| x.unwrap()).take(shdr.virt_size as usize).collect();
            let name = String::from_utf8(shdr.name.as_bytes().to_vec()).unwrap();
            sections.insert(name.clone(), Section {
                name: name,
                addr: shdr.virt_addr,
                offset: shdr.virt_addr - base_img,
                size: shdr.virt_size as u64,
                data: data,
            });
        }

        Ok(File {
            file_hdr: types::FileHeader {
                machine: machine,
                num_sections: num_sections,
                create_time: create_time,
                sym_tab_ptr: sym_tab_ptr,
                num_sym: num_sym,
                opt_hdr_size: opt_hdr_size,
                characteristics: characteristics,
            },
            opt_hdr: types::OptionalHeader {
                magic: magic,
                maj_link_ver: maj_link_ver,
                min_link_ver: min_link_ver,
                code_size: code_size,
                init_size: init_size,
                uninit_size: uninit_size,
                enter_addr: enter_addr,
                base_code: base_code,
                base_data: base_data,
                base_img: base_img,
                align_sec: align_sec,
                align_file: align_file,
                maj_op_ver: maj_op_ver,
                min_op_ver: min_op_ver,
                maj_img_ver: maj_img_ver,
                min_img_ver: min_img_ver,
                maj_sub_ver: maj_sub_ver,
                min_sub_ver: min_sub_ver,
                win_ver_val: win_ver_val,
                img_size: img_size,
                hdr_size: hdr_size,
                chksum: chksum,
                subsys: subsys,
                dll_char: dll_char,
                stack_rsrv_size: stack_rsrv_size,
                stack_commit_size: stack_commit_size,
                heap_rsrv_size: heap_rsrv_size,
                heap_commit_size: heap_commit_size,
                loader_flags: loader_flags,
                num_rva: num_rva,
            },
            sections: sections,
        })
    }

    pub fn sections(&self) -> &HashMap<String, Section> {
        &self.sections
    }
}

impl fmt::Display for File {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PE file")
    }
}

impl Object for File {
    fn arch(&self) -> ::Arch {
        match self.file_hdr.machine {
            types::PM_AMD6 => ::Arch::X86(::Width::W64),
            types::PM_I386 => ::Arch::X86(::Width::W32),
            types::PM_ARM => ::Arch::ARM(::Width::W32, ::Endianness::Little, ::ARMMode::ARM, ::ARMType::ARM),
            _ => ::Arch::Unknown,

        }
    }
    fn get_section(&self, name: &str) -> Option<&Section> {
        self.sections.get(name)
    }
}
