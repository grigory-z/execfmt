#![feature(cstr_to_str,collections)]
extern crate byteorder;

pub mod pe;
pub mod elf;

#[derive(Clone, Copy)]
pub enum Arch {
    X86(Width),
    ARM(Width, Endianness, ARMMode, ARMType),
    PPC(Width, Endianness),
    Unknown,
}

#[derive(Clone, Copy)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Clone, Copy)]
pub enum Width {
    W16,
    W32,
    W64,
}

#[derive(Clone, Copy)]
pub enum ARMMode {
    ARM,
    Thumb,
}

#[derive(Clone, Copy)]
pub enum ARMType {
    ARM,
    MClass,
    V8,
}

pub trait Object {
    fn arch(&self) -> Arch;
}
