pub mod exe;
pub mod dll;
pub mod sideload;
pub mod cpl;
pub mod xll;
pub mod pic;
pub mod service;
pub mod powershell;

#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Exe,
    Dll,
    Sideload { target_dll: String },
    Cpl,
    Xll,
    Pic,
    Service,
    PowerShell,
}
