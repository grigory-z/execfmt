#![feature(cstr_to_str,collections)]
extern crate byteorder;

pub mod pe;
pub mod elf;

#[derive(Clone, Copy)]
pub enum Arch {
    X86(Width),
    ARM(Width, Endian, ARMMode, ARMType),
    PPC(Width, Endian),
}

#[derive(Clone, Copy)]
pub enum Endian {
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
