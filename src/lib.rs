extern crate byteorder;
extern crate libc;

pub mod pe;
pub mod elf;
pub mod mach;

use std::io;
use std::error;
use std::fmt;
use std::default;

pub struct Error {
    inner: Option<Box<error::Error>>,
    desc: String,
}

impl error::Error for Error {
    fn description(&self) -> &str {
        &self.desc
    }
    fn cause(&self) -> Option<&error::Error> {
        self.inner.as_ref().map(|x| &**x)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(w, "Error: {}{}", self.desc, match self.inner {
            Some(ref x) => {
                format!(" ({})", x.description())
            }
            None => format!(""),
        })
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(w, "execfmt error: desc: {} inner: {}", self.desc, match self.inner {
            Some(ref x) => x.description(),
            None => "None",
        })
    }
}

impl<'a> From<&'a str> for Error {
    fn from(s: &'a str) -> Error {
        Error {
            inner: None,
            desc: String::from(s),
        }
    }
}

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
    fn get_section(&self, name: &str) -> Option<&Section>;
}

#[derive(Debug)]
pub struct Section {
    name: String,
    addr: u64,
    offset: u64,
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
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl default::Default for Section {
    fn default() -> Section {
        Section {
            name: String::from(""),
            addr: 0,
            offset: 0,
            size: u64::max_value(),
            data: Vec::new(),
        }
    }
}

pub fn parse<R: io::Read + io::Seek>(r: &mut R) -> Result<Box<Object>, Box<error::Error>> {
    if let Ok(x) = elf::File::parse(r) {
        Ok(Box::new(x))
    } else if let Ok(x) = pe::File::parse(r) {
        Ok(Box::new(x))
    } else if let Ok(x) = mach::File::parse(r) {
        Ok(Box::new(x))
    } else {
        Err(Box::new(Error::from("Invalid format")))
    }
}
