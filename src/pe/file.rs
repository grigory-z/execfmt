use std::io::prelude::*;
use std::io;
use std::path::Path;
use std::fs;
use std::fmt;
use std::str;
use std::ffi;
use byteorder;
use byteorder::ReadBytesExt;
use pe;
use std::collections::HashMap;

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

pub struct Section {
    hdr: pe::SectionHeader,
    data: Vec<u8>,
}

impl Section {
    pub fn header(&self) -> &pe::SectionHeader {
        &self.hdr
    }
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PE section '{:?}' from {:#x} to {:#x}", self.hdr.name, self.hdr.virt_addr, self.hdr.virt_addr + self.hdr.virt_size as u64)
    }
}

pub struct File {
    file_hdr: pe::FileHeader,
    opt_hdr: pe::OptionalHeader,
    sections: HashMap<String, Section>,
}

impl File {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<File, io::Error> {
        let rf = try!(fs::File::open(path));
        let mut f = io::BufReader::new(rf);

        let dossig = try!(read_u16!(f));

        if dossig != pe::DOS_HDR_MAG {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid DOS signature"));
        }

        try!(f.seek(io::SeekFrom::Start(0x3c)));

        let foff = try!(read_u32!(f));

        try!(f.seek(io::SeekFrom::Start(foff as u64)));

        println!("Seeking to {:#x}", foff);

        let pesig = try!(read_u32!(f));

        if pesig != pe::PE_HDR_MAG {
            println!("{:#x} sig", pesig);
            return Err(io::Error::new(io::ErrorKind::Other, "invalid PE signature"));
        }

        let machine = pe::Machine(try!(read_u16!(f)));
        let num_sections = try!(read_u16!(f));
        let create_time = try!(read_u32!(f));
        let _ = try!(read_u32!(f));
        let _ = try!(read_u32!(f));
        let opt_hdr_size = try!(read_u16!(f));
        let characteristics = try!(read_u16!(f));

        println!("machine is {:?}", machine);
        println!("{:?} sections", num_sections);
        println!("time is: {:?}", create_time);
        println!("optional header size: {:?}", opt_hdr_size);
        println!("characteristics: {:?}", characteristics);

        if opt_hdr_size == 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "optional header missing"));
        }

        let magic = pe::Class(try!(read_u16!(f)));
        let maj_link_ver = try!(read_u8!(f));
        let min_link_ver = try!(read_u8!(f));
        let code_size = try!(read_u32!(f));
        let init_size = try!(read_u32!(f));
        let uninit_size = try!(read_u32!(f));
        let enter_addr = try!(read_u32!(f));
        let base_code = try!(read_u32!(f));
        let base_data = {
            if magic == pe::PECLASS64 {
                0
            } else {
                try!(read_u32!(f))
            }
        };
        let base_img = {
            if magic == pe::PECLASS64 {
                try!(read_u64!(f))
            } else {
                try!(read_u32!(f)) as u64
            }
        };
        let align_sec = try!(read_u32!(f));
        let align_file = try!(read_u32!(f));
        let maj_op_ver = try!(read_u16!(f));
        let min_op_ver = try!(read_u16!(f));
        let maj_img_ver = try!(read_u16!(f));
        let min_img_ver = try!(read_u16!(f));
        let maj_sub_ver = try!(read_u16!(f));
        let min_sub_ver = try!(read_u16!(f));
        let win_ver_val = try!(read_u32!(f));
        let img_size = try!(read_u32!(f));
        let hdr_size = try!(read_u32!(f));
        let chksum = try!(read_u32!(f));
        let subsys = try!(read_u16!(f));
        let dll_char = try!(read_u16!(f));
        let stack_rsrv_size = {
            if magic == pe::PECLASS64 {
                try!(read_u64!(f))
            } else {
                try!(read_u32!(f)) as u64
            }
        };
        let stack_commit_size = {
            if magic == pe::PECLASS64 {
                try!(read_u64!(f))
            } else {
                try!(read_u32!(f)) as u64
            }
        };
        let heap_rsrv_size = {
            if magic == pe::PECLASS64 {
                try!(read_u64!(f))
            } else {
                try!(read_u32!(f)) as u64
            }
        };
        let heap_commit_size = {
            if magic == pe::PECLASS64 {
                try!(read_u64!(f))
            } else {
                try!(read_u32!(f)) as u64
            }
        };
        let loader_flags = try!(read_u32!(f));
        let num_rva = try!(read_u32!(f));

        println!("bits: {:?}", magic);
        println!("major linker version: {:#x}", maj_link_ver);
        println!("minor linker version: {:#x}", min_link_ver);
        println!("code size: {:#x}", code_size);
        println!("initialized size: {:#x}", init_size);
        println!("uninitialized size: {:#x}", uninit_size);
        println!("entry point address: {:#x}", enter_addr);
        println!("base of code: {:#x}", base_code);
        println!("base of data: {:#x}", base_data);
        println!("base of image: {:#x}", base_img);
        println!("major OS version: {:#x}", maj_op_ver);
        println!("minor OS version: {:#x}", min_op_ver);
        println!("num_rva is {}", num_rva);

        try!(f.seek(io::SeekFrom::Start((foff as u64+opt_hdr_size as u64+0x18))));

        let mut sections_lst = Vec::new();
        let mut sections = HashMap::new();

        for _ in 0..num_sections {
            let mut name = [0u8; 8];

            try!(f.read(&mut name));

            let mut name_str = name.as_ref();

            if (name.contains(&0)) {
                name_str = &name_str[..name.position_elem(&0).unwrap()]
            }

            let virt_size = try!(read_u32!(f));
            let virt_addr = try!(read_u32!(f)) as u64 + base_img;
            let data_size = try!(read_u32!(f));
            let raw_ptr = try!(read_u32!(f));
            let reloc_ptr = try!(read_u32!(f));
            let line_no_ptr = try!(read_u32!(f));
            let num_relocs = try!(read_u16!(f));
            let num_line_no = try!(read_u16!(f));
            let characteristics = try!(read_u32!(f));
            let name =  ffi::CString::new(name_str).unwrap();

            sections_lst.push(pe::SectionHeader {
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
            try!(f.seek(io::SeekFrom::Start(shdr.raw_ptr as u64)));
            let data: Vec<u8> = io::Read::by_ref(&mut f).bytes().map(|x| x.unwrap()).take(shdr.virt_size as usize).collect();
            sections.insert(String::from_str(shdr.name.to_str().unwrap()), Section {
                hdr: shdr,
                data: data,
            });
        }


        Ok(File {
            file_hdr: pe::FileHeader {
                machine: machine,
                num_sections: num_sections,
                create_time: create_time,
                opt_hdr_size: opt_hdr_size,
                characteristics: characteristics,
            },
            opt_hdr: pe::OptionalHeader {
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

