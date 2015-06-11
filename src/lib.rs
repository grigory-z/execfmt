#![feature(cstr_to_str,collections,convert)]
extern crate byteorder;

pub mod pe;
pub mod elf;

use std::io;

#[derive(Clone, Debug, Copy)]
pub enum Arch {
    X86(Width),
    ARM(Width, Endianness, ARMMode, ARMType),
    PPC(Width, Endianness),
    Unknown,
}

#[derive(Clone, Debug, Copy)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Clone, Debug, Copy)]
pub enum Width {
    W16,
    W32,
    W64,
}

#[derive(Clone, Debug, Copy)]
pub enum ARMMode {
    ARM,
    Thumb,
}

#[derive(Clone, Debug, Copy)]
pub enum ARMType {
    ARM,
    MClass,
    V8,
}

pub trait Object {
    fn arch(&self) -> Arch;
    fn get_section(&self, name: &str) -> Option<Section>;
}

pub struct Section {
    name: String,
    addr: u64,
    size: u64,
    data: Vec<u8>,
}

impl Section {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn addr(&self) -> u64 {
        self.addr
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

pub fn parse<R: io::Read + io::Seek>(r: &mut R) -> Option<Box<Object>> {
    if let Ok(x) = elf::File::parse(r) {
        Some(Box::new(x))
    } else if let Ok(x) = pe::File::parse(r) {
        Some(Box::new(x))
    } else {
        None
    }
}
