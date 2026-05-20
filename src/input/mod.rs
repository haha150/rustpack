pub mod shellcode;
pub mod dotnet;
pub mod pe;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InputFormat {
    Shellcode,
    DotNet,
    NativePE,
}
